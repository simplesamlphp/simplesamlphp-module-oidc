<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\ClientAssertionTypesEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

class ClientAuthenticationRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        protected ModuleConfig $moduleConfig,
        protected JwksResolver $jwksResolver,
    ) {
        parent::__construct($requestParamsResolver);
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

        // Let's check if client secret is provided.
        /** @var ?string $clientSecret */
        $clientSecret = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::ClientSecret->value,
            $request,
            $allowedServerRequestMethods,
        ) ?? $request->getServerParams()['PHP_AUTH_PW'] ?? null;

        if ($clientSecret) {
            hash_equals($client->getSecret(), $clientSecret) || throw OidcServerException::invalidClient($request);
            return new Result($this->getKey(), ParamsEnum::ClientSecret->value);
        }

        // No client_secret provided, meaning client_secret_post or client_secret_basic client authentication methods
        // were not used. Let's check for private_key_jwt method.
        $clientAssertionParam = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::Request->value,
            $request,
            $allowedServerRequestMethods,
        );

        if (is_null($clientAssertionParam)) {
            throw OidcServerException::accessDenied('Not a single client authentication method presented.');
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

        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();

        ($jwks = $this->jwksResolver->forClient($client)) || throw OidcServerException::accessDenied(
            'Can not validate Client Assertion, client JWKS not available.',
        );

        try {
            $clientAssertion->verifyWithKeySet($jwks);
        } catch (\Throwable $exception) {
            throw OidcServerException::accessDenied(
                'Client Assertion validation failed: ' . $exception->getMessage(),
            );
        }

        ($client->getIdentifier() === $clientAssertion->getIssuer()) || throw OidcServerException::accessDenied(
            'Invalid Client Assertion Issuer claim.',
        );

        ($client->getIdentifier() === $clientAssertion->getSubject()) || throw OidcServerException::accessDenied(
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
        throw OidcServerException::accessDenied('Invalid Client Assertion Audience claim.');

        return new Result($this->getKey(), ParamsEnum::ClientAssertion->value);
    }
}
