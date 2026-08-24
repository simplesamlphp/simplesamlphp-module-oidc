<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\StatusList\SubjectRefHasher;

#[CoversClass(SubjectRefHasher::class)]
#[AllowMockObjectsWithoutExpectations]
class SubjectRefHasherTest extends TestCase
{
    protected MockObject $moduleConfigMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getEncryptionKey')->willReturn('a-secret-salt');
    }


    protected function sut(?ModuleConfig $moduleConfig = null): SubjectRefHasher
    {
        return new SubjectRefHasher($moduleConfig ?? $this->moduleConfigMock);
    }


    public function testProducesAValueSizedForItsColumn(): void
    {
        $hash = $this->sut()->hash('student@example.org');

        $this->assertSame(64, strlen($hash));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }


    public function testIsStableForTheSameIdentifier(): void
    {
        $this->assertSame(
            $this->sut()->hash('student@example.org'),
            $this->sut()->hash('student@example.org'),
        );
    }


    public function testDistinguishesIdentifiers(): void
    {
        $this->assertNotSame(
            $this->sut()->hash('student@example.org'),
            $this->sut()->hash('teacher@example.org'),
        );
    }


    /**
     * The point of keying the hash is that an identifier with little entropy, such as an email address,
     * can not be confirmed by guessing it and hashing. Whoever holds the database but not the key must
     * get nothing, so a different key has to produce a different value for the same identifier.
     */
    public function testDependsOnTheKeyAndNotOnlyOnTheIdentifier(): void
    {
        $otherConfig = $this->createMock(ModuleConfig::class);
        $otherConfig->method('getEncryptionKey')->willReturn('a-different-secret-salt');

        $this->assertNotSame(
            $this->sut()->hash('student@example.org'),
            $this->sut($otherConfig)->hash('student@example.org'),
        );
    }


    /**
     * A plain SHA-256 of the identifier is exactly what this must not be.
     */
    public function testIsNotAnUnkeyedDigestOfTheIdentifier(): void
    {
        $this->assertNotSame(
            hash('sha256', 'student@example.org'),
            $this->sut()->hash('student@example.org'),
        );
    }


    /**
     * Deriving the key from the module's encryption key means there is no separate secret to manage,
     * but it must not be usable as, or derivable back to, that key.
     */
    public function testDoesNotKeyTheHashWithTheEncryptionKeyDirectly(): void
    {
        $this->assertNotSame(
            hash_hmac('sha256', 'student@example.org', 'a-secret-salt'),
            $this->sut()->hash('student@example.org'),
        );
    }
}
