<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Repositories\CodeChallengeVerifiersRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use Throwable;

class CodeChallengeMethodRule extends AbstractRule
{
    /**
     * @var CodeChallengeVerifiersRepository
     */
    protected $codeChallengeVerifiersRepository;

    public function __construct(CodeChallengeVerifiersRepository $codeChallengeVerifiersRepository)
    {
        $this->codeChallengeVerifiersRepository = $codeChallengeVerifiersRepository;
    }

    /**
     * @throws Throwable
     * @throws OidcServerException
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface {
        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var string|null $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        $codeChallengeMethod = $request->getQueryParams()['code_challenge_method'] ?? 'plain';
        $codeChallengeVerifiers = $this->codeChallengeVerifiersRepository->getAll();

        if (array_key_exists($codeChallengeMethod, $codeChallengeVerifiers) === false) {
            throw OidcServerException::invalidRequest(
                'code_challenge_method',
                'Code challenge method must be one of ' . implode(', ', array_map(
                    function ($method) {
                        return '`' . $method . '`';
                    },
                    array_keys($codeChallengeVerifiers)
                )),
                null,
                $redirectUri,
                $state,
                $useFragmentInHttpErrorResponses
            );
        }

        return new Result($this->getKey(), $codeChallengeMethod);
    }
}
