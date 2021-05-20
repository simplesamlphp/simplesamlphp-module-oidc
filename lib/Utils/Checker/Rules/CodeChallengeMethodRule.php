<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Repositories\CodeChallengeVerifiersRepository;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\RequestRuleInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Result;

class CodeChallengeMethodRule implements RequestRuleInterface
{
    /**
     * @var CodeChallengeVerifiersRepository
     */
    protected $codeChallengeVerifiersRepository;

    public function __construct(CodeChallengeVerifiersRepository $codeChallengeVerifiersRepository)
    {
        $this->codeChallengeVerifiersRepository = $codeChallengeVerifiersRepository;
    }

    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data
    ): ?ResultInterface {
        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::getKey())->getValue();
        /** @var string|null $state */
        $state = $currentResultBag->getOrFail(StateRule::getKey())->getValue();

        $codeChallengeMethod = $request->getQueryParams()['code_challenge_method'] ?? 'plain';
        $codeChallengeVerifiers = $this->codeChallengeVerifiersRepository->getAll();

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
                $redirectUri,
                $state
            );
        }

        return new Result(self::getKey(), $codeChallengeMethod);
    }

    public static function getKey(): string
    {
        return 'code_challenge_method';
    }
}
