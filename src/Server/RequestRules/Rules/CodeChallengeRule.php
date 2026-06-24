<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * @extends AbstractRule<string|null>
 */
class CodeChallengeRule extends AbstractRule
{
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
        $loggerService->debug('CodeChallengeRule::checkRule');

        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();
        $redirectUri = $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        $codeChallenge = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::CodeChallenge->value,
            $request,
            $allowedServerRequestMethods,
        );

        if ($codeChallenge === null) {
            if (! $client->isConfidential()) {
                throw OidcServerException::invalidRequest(
                    ParamsEnum::CodeChallenge->value,
                    'Code Challenge must be provided for public clients.',
                    null,
                    $redirectUri,
                    $state,
                    $responseMode,
                );
            }

            return new Result($this->getKey(), null);
        }

        // Validate code_challenge according to RFC-7636
        // @see: https://tools.ietf.org/html/rfc7636#section-4.2
        if (preg_match('/^[A-Za-z0-9-._~]{43,128}$/', $codeChallenge) !== 1) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::CodeChallenge->value,
                'Code Challenge must follow the specifications of RFC-7636.',
                null,
                $redirectUri,
                $state,
                $responseMode,
            );
        }

        return new Result($this->getKey(), $codeChallenge);
    }
}
