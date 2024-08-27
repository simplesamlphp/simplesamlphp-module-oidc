<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Repositories\CodeChallengeVerifiersRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

class CodeChallengeMethodRule extends AbstractRule
{
    public function __construct(
        ParamsResolver $paramsResolver,
        protected CodeChallengeVerifiersRepository $codeChallengeVerifiersRepository,
    ) {
        parent::__construct($paramsResolver);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?ResultInterface {
        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var string|null $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        // TODO mivanci continue refactoring to paramsResolver:
        $codeChallengeMethod = $this->getRequestParamBasedOnAllowedMethods(
            'code_challenge_method',
            $request,
            $loggerService,
            $allowedServerRequestMethods,
        ) ?? 'plain';
        $codeChallengeVerifiers = $this->codeChallengeVerifiersRepository->getAll();

        if (array_key_exists($codeChallengeMethod, $codeChallengeVerifiers) === false) {
            throw OidcServerException::invalidRequest(
                'code_challenge_method',
                'Code challenge method must be one of ' . implode(', ', array_map(
                    fn($method) => '`' . $method . '`',
                    array_keys($codeChallengeVerifiers),
                )),
                null,
                $redirectUri,
                $state,
                $useFragmentInHttpErrorResponses,
            );
        }

        return new Result($this->getKey(), $codeChallengeMethod);
    }
}
