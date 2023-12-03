<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories;

use League\OAuth2\Server\CodeChallengeVerifiers\CodeChallengeVerifierInterface;
use League\OAuth2\Server\CodeChallengeVerifiers\PlainVerifier;
use League\OAuth2\Server\CodeChallengeVerifiers\S256Verifier;

use function hash_algos;
use function in_array;

class CodeChallengeVerifiersRepository
{
    /**
     * @var CodeChallengeVerifierInterface[]
     */
    protected array $codeChallengeVerifiers = [];

    public function __construct()
    {
        if (in_array('sha256', hash_algos(), true)) {
            $s256Verifier = new S256Verifier();
            $this->codeChallengeVerifiers[$s256Verifier->getMethod()] = $s256Verifier;
        }

        $plainVerifier = new PlainVerifier();
        $this->codeChallengeVerifiers[$plainVerifier->getMethod()] = $plainVerifier;
    }

    /**
     * @return CodeChallengeVerifierInterface[]
     */
    public function getAll(): array
    {
        return $this->codeChallengeVerifiers;
    }

    /**
     * @return CodeChallengeVerifierInterface|null Verifier for the method or null if not supported.
     */
    public function get(string $method): ?CodeChallengeVerifierInterface
    {
        return $this->codeChallengeVerifiers[$method] ?? null;
    }

    public function has(string $method): bool
    {
        return isset($this->codeChallengeVerifiers[$method]);
    }
}
