<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

class CodeChallengeRule extends AbstractRule
{
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
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET->value],
    ): ?ResultInterface {
        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var string|null $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        $codeChallenge = $this->getParamFromRequestBasedOnAllowedMethods(
            'code_challenge',
            $request,
            $loggerService,
            $allowedServerRequestMethods,
        );

        if ($codeChallenge === null) {
            throw OidcServerException::invalidRequest(
                'code_challenge',
                'Code challenge must be provided for public clients',
                null,
                $redirectUri,
                $state,
                $useFragmentInHttpErrorResponses,
            );
        }

        // Validate code_challenge according to RFC-7636
        // @see: https://tools.ietf.org/html/rfc7636#section-4.2
        if (preg_match('/^[A-Za-z0-9-._~]{43,128}$/', $codeChallenge) !== 1) {
            throw OidcServerException::invalidRequest(
                'code_challenge',
                'Code challenge must follow the specifications of RFC-7636.',
                null,
                $redirectUri,
                $state,
                $useFragmentInHttpErrorResponses,
            );
        }

        return new Result($this->getKey(), $codeChallenge);
    }
}
