<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\ClientAssertionTypesEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

class ClientAuthenticationRule extends AbstractRule
{
    protected const string KEY_CLIENT_ASSERTION_JTI = 'client_assertion_jti';


    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected ModuleConfig $moduleConfig,
        protected JwksResolver $jwksResolver,
        protected ?ProtocolCache $protocolCache,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?ResultInterface {
        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();

        // We will only perform client authentication if the client type is confidential.
        if (!$client->isConfidential()) {
            return new Result($this->getKey(), null);
        }

        // The refusal of a client which does not authenticate (RFC 6749 section 5.2, RFC 7521 section 4.2.1):
        // invalid_client, HTTP 401, with a WWW-Authenticate challenge when the request used the Authorization header.
        // The answer does not say why, the log does.
        $refuse = static function (string $reason) use ($client, $request, $loggerService): OidcServerException {
            $loggerService->warning(
                'Client authentication failed: ' . $reason,
                ['client_id' => $client->getIdentifier()],
            );

            return OidcServerException::invalidClient($request);
        };

        // Let's check if client secret is provided.
        /** @var ?string $clientSecret */
        $clientSecret = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::ClientSecret->value,
            $request,
            $allowedServerRequestMethods,
        ) ?? $request->getServerParams()['PHP_AUTH_PW'] ?? null;

        if ($clientSecret) {
            hash_equals($client->getSecret(), $clientSecret) || throw $refuse('Client secret does not match.');
            return new Result($this->getKey(), ParamsEnum::ClientSecret->value);
        }

        // No client_secret provided, meaning client_secret_post or client_secret_basic client authentication methods
        // were not used. Let's check for private_key_jwt method.
        $clientAssertionParam = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::ClientAssertion->value,
            $request,
            $allowedServerRequestMethods,
        );

        if (is_null($clientAssertionParam)) {
            throw $refuse('Not a single client authentication method presented.');
        }

        // private_key_jwt authentication method is used.
        // Check the expected assertion type param.
        $clientAssertionType = $this->requestParamsResolver->getfromRequestBasedOnAllowedMethods(
            ParamsEnum::ClientAssertionType->value,
            $request,
            $allowedServerRequestMethods,
        );

        if ($clientAssertionType !== ClientAssertionTypesEnum::JwtBaerer->value) {
            throw OidcServerException::invalidRequest(ParamsEnum::ClientAssertionType->value);
        }

        $clientAssertion = $this->requestParamsResolver->parseClientAssertionToken($clientAssertionParam);

        // Check if the Client Assertion token has already been used. Only applicable if we have cache available.
        if ($this->protocolCache) {
            ($this->protocolCache->has(self::KEY_CLIENT_ASSERTION_JTI, $clientAssertion->getJwtId()) === false)
            || throw OidcServerException::invalidRequest(
                ParamsEnum::ClientAssertion->value,
                'Client Assertion reused.',
            );
        }

        ($jwks = $this->jwksResolver->forClient($client)) || throw $refuse(
            'Can not validate Client Assertion, client JWKS not available.',
        );

        try {
            $clientAssertion->verifyWithKeySet($jwks);
        } catch (\Throwable $exception) {
            throw $refuse('Client Assertion validation failed: ' . $exception->getMessage());
        }

        ($client->getIdentifier() === $clientAssertion->getIssuer()) || throw $refuse(
            'Invalid Client Assertion Issuer claim.',
        );

        ($client->getIdentifier() === $clientAssertion->getSubject()) || throw $refuse(
            'Invalid Client Assertion Subject claim.',
        );

        // OpenID Core spec: The Audience SHOULD be the URL of the Authorization Server's Token Endpoint.
        // OpenID Federation spec: ...the audience of the signed JWT MUST be either the URL of the Authorization
        //     Server's Authorization Endpoint or the Authorization Server's Entity Identifier.
        $expectedAudience = [
            $this->moduleConfig->getModuleUrl(RoutesEnum::Token->value),
            $this->moduleConfig->getModuleUrl(RoutesEnum::Authorization->value),
            $this->moduleConfig->getIssuer(),
        ];

        (!empty(array_intersect($expectedAudience, $clientAssertion->getAudience()))) ||
        throw $refuse('Invalid Client Assertion Audience claim.');

        // Everything seems ok. Save it in cache so we can check for reuse.
        $this->protocolCache?->set(
            $clientAssertion->getJwtId(),
            $this->helpers->dateTime()->getSecondsToExpirationTime($clientAssertion->getExpirationTime()),
            self::KEY_CLIENT_ASSERTION_JTI,
            $clientAssertion->getJwtId(),
        );

        return new Result($this->getKey(), ParamsEnum::ClientAssertion->value);
    }
}
