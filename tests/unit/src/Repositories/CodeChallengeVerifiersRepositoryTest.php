<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use League\OAuth2\Server\CodeChallengeVerifiers\CodeChallengeVerifierInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Repositories\CodeChallengeVerifiersRepository;

#[CoversClass(CodeChallengeVerifiersRepository::class)]
class CodeChallengeVerifiersRepositoryTest extends TestCase
{
    protected function sut(): CodeChallengeVerifiersRepository
    {
        return new CodeChallengeVerifiersRepository();
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(CodeChallengeVerifiersRepository::class, $this->sut());
    }

    public function testCanGetCodeChallengeVerifier(): void
    {
        $this->assertInstanceOf(
            CodeChallengeVerifierInterface::class,
            $this->sut()->get('S256'),
        );
        $this->assertTrue($this->sut()->has('S256'));

        $this->assertInstanceOf(
            CodeChallengeVerifierInterface::class,
            $this->sut()->get('plain'),
        );
        $this->assertTrue($this->sut()->has('plain'));

        $this->assertNotEmpty($this->sut()->getAll());
    }

    public function testReturnsNullForUnsuportedVerifier(): void
    {
        $this->assertNull($this->sut()->get('unsuported'));
    }
}
