<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Jwks;

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
        /** @var string|null $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        $idTokenHintParam = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::IdTokenHint->value,
            $request,
            $allowedServerRequestMethods,
        );

        if ($idTokenHintParam === null) {
            return new Result($this->getKey(), $idTokenHintParam);
        }

        if (empty($idTokenHintParam)) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::IdTokenHint->value,
                'Received empty id_token_hint',
                null,
                null,
                $state,
            );
        }

        $jwks = $this->jwks->jwksDecoratorFactory()->fromJwkDecorators(
            ...$this->moduleConfig->getProtocolSignatureKeyPairBag()->getAllPublicKeys(),
        )->jsonSerialize();

        $idTokenHint = $this->core->idTokenFactory()->fromToken($idTokenHintParam);

        if ($idTokenHint->getIssuer() !== $this->moduleConfig->getIssuer()) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::IdTokenHint->value,
                'Invalid ID Token Hint Issuer',
                null,
                null,
                $state,
            );
        }

        try {
            $idTokenHint->verifyWithKeySet($jwks);
        } catch (\Throwable $exception) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::IdTokenHint->value,
                $exception->getMessage(),
                null,
                null,
                $state,
            );
        }


        return new Result($this->getKey(), $idTokenHint);
    }
}
