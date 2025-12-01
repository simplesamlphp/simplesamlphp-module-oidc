<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

class CodeVerifierRule extends AbstractRule
{
    /**
     * @inheritDoc
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
        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();

        $codeVerifier = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::CodeVerifier->value,
            $request,
            $allowedServerRequestMethods,
        );

        if (is_null($codeVerifier)) {
            if (!$client->isConfidential()) {
                throw OidcServerException::invalidRequest(
                    'code_verifier',
                    'Code Verifier must be provided for public clients.',
                );
            }

            return new Result($this->getKey(), null);
        }

        // Validate code_verifier according to RFC-7636
        // @see: https://tools.ietf.org/html/rfc7636#section-4.1
        if (preg_match('/^[A-Za-z0-9-._~]{43,128}$/', $codeVerifier) !== 1) {
            throw OidcServerException::invalidRequest(
                'code_verifier',
                'Code Verifier must follow the specifications of RFC-7636.',
            );
        }

        return new Result($this->getKey(), $codeVerifier);
    }
}
