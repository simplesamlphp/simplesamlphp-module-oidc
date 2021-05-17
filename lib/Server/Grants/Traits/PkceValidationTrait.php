<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\Grants\Traits;

use League\OAuth2\Server\CodeChallengeVerifiers\CodeChallengeVerifierInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;

trait PkceValidationTrait
{
    /**
     * @param ServerRequestInterface $request
     * @param string $redirectUri
     * @param string|null $state
     * @return string
     * @throws OidcServerException
     */
    protected function getCodeChallengeOrFail(
        ServerRequestInterface $request,
        string $redirectUri,
        string $state = null
    ): string {
        $codeChallenge = $request->getQueryParams()['code_challenge'] ?? null;

        if ($codeChallenge === null) {
            throw OidcServerException::invalidRequest(
                'code_challenge',
                'Code challenge must be provided for public clients',
                null,
                $redirectUri,
                $state
            );
        }

        // Validate code_challenge according to RFC-7636
        // @see: https://tools.ietf.org/html/rfc7636#section-4.2
        if (\preg_match('/^[A-Za-z0-9-._~]{43,128}$/', $codeChallenge) !== 1) {
            throw OidcServerException::invalidRequest(
                'code_challenge',
                'Code challenge must follow the specifications of RFC-7636.',
                null,
                $redirectUri
            );
        }

        return $codeChallenge;
    }

    /**
     * @param ServerRequestInterface $request
     * @param CodeChallengeVerifierInterface[] $codeChallengeVerifiers
     * @param string $redirectUri
     * @return string
     * @throws OidcServerException
     */
    protected function getCodeChallengeMethodOrFail(
        ServerRequestInterface $request,
        array $codeChallengeVerifiers,
        string $redirectUri
    ): string {
        $codeChallengeMethod = $request->getQueryParams()['code_challenge_method'] ?? 'plain';

        if (\array_key_exists($codeChallengeMethod, $codeChallengeVerifiers) === false) {
            throw OidcServerException::invalidRequest(
                'code_challenge_method',
                'Code challenge method must be one of ' . \implode(', ', \array_map(
                    function ($method) {
                        return '`' . $method . '`';
                    },
                    \array_keys($codeChallengeVerifiers)
                )),
                null,
                $redirectUri
            );
        }

        return $codeChallengeMethod;
    }
}
