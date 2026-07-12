<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Jwks;

/**
 * @extends AbstractRule<\SimpleSAML\OpenID\Core\IdToken|null>
 */
class IdTokenHintRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Jwks $jwks,
        protected readonly Core $core,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }

    /**
     * @inheritDoc
     *
     * @throws \Throwable
     *
     * @param ResponseModeInterface $responseMode
     * @param HttpMethodsEnum[] $allowedServerRequestMethods
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        // When this rule runs in the authorization flow, the redirect URI has already been validated and is
        // available in the result bag, so validation errors can be redirected back to the client (as required at
        // the authorization endpoint). In the logout (end session) flow there is no ClientRedirectUriRule, so this
        // resolves to null and the error is returned directly, preserving the previous behavior.
        $redirectUriValue = $currentResultBag->get(ClientRedirectUriRule::class)?->getValue();
        $redirectUri = is_string($redirectUriValue) ? $redirectUriValue : null;

        $idTokenHintParam = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::IdTokenHint->value,
            $request,
            $allowedServerRequestMethods,
        );

        if ($idTokenHintParam === null) {
            return new Result($this->getKey(), $idTokenHintParam);
        }

        if (empty($idTokenHintParam)) {
            $loggerService->notice('Request rejected: `id_token_hint` was provided but empty.');
            throw OidcServerException::invalidRequest(
                ParamsEnum::IdTokenHint->value,
                'Received empty id_token_hint',
                null,
                $redirectUri,
                $state,
                $responseMode,
            );
        }

        $jwks = $this->jwks->jwksDecoratorFactory()->fromJwkDecorators(
            ...$this->moduleConfig->getProtocolSignatureKeyPairBag()->getAllPublicKeys(),
        )->jsonSerialize();

        $idTokenHint = $this->core->idTokenFactory()->fromToken($idTokenHintParam);

        if ($idTokenHint->getIssuer() !== $this->moduleConfig->getIssuer()) {
            $loggerService->notice(
                'Request rejected: `id_token_hint` was not issued by this OP.',
                ['issuer' => $idTokenHint->getIssuer(), 'expected_issuer' => $this->moduleConfig->getIssuer()],
            );
            throw OidcServerException::invalidRequest(
                ParamsEnum::IdTokenHint->value,
                'Invalid ID Token Hint Issuer',
                null,
                $redirectUri,
                $state,
                $responseMode,
            );
        }

        try {
            $idTokenHint->verifyWithKeySet($jwks);
        } catch (\Throwable $exception) {
            $loggerService->notice(
                'Request rejected: `id_token_hint` signature verification failed.',
                ['exception' => $exception->getMessage()],
            );
            throw OidcServerException::invalidRequest(
                ParamsEnum::IdTokenHint->value,
                $exception->getMessage(),
                null,
                $redirectUri,
                $state,
                $responseMode,
            );
        }


        return new Result($this->getKey(), $idTokenHint);
    }
}
