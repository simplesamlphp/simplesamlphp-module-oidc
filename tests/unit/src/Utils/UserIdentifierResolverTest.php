<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Utils\UserIdentifierResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\UserIdentifierResolver
 */
class UserIdentifierResolverTest extends TestCase
{
    protected function sut(): UserIdentifierResolver
    {
        return new UserIdentifierResolver();
    }

    public function testResolvesSingleCandidate(): void
    {
        $this->assertSame(
            'user-1',
            $this->sut()->resolve(['uid'], ['uid' => ['user-1']]),
        );
    }

    public function testRespectsCandidatePriority(): void
    {
        $attributes = [
            'uid' => ['fallback'],
            'eduPersonPrincipalName' => ['preferred'],
        ];

        $this->assertSame(
            'preferred',
            $this->sut()->resolve(['eduPersonPrincipalName', 'uid'], $attributes),
        );
    }

    public function testFallsBackToLaterCandidateWhenEarlierMissing(): void
    {
        $this->assertSame(
            'fallback',
            $this->sut()->resolve(['eduPersonPrincipalName', 'uid'], ['uid' => ['fallback']]),
        );
    }

    public function testSkipsCandidatesWithEmptyValue(): void
    {
        $attributes = [
            'eduPersonPrincipalName' => [''],
            'uid' => ['present'],
        ];

        $this->assertSame(
            'present',
            $this->sut()->resolve(['eduPersonPrincipalName', 'uid'], $attributes),
        );
    }

    public function testReturnsNullWhenNoCandidateMatches(): void
    {
        $this->assertNull(
            $this->sut()->resolve(['eduPersonPrincipalName', 'uid'], ['mail' => ['user@example.org']]),
        );
    }

    public function testReturnsNullForNonArrayOrEmptyAttributeValues(): void
    {
        $this->assertNull(
            $this->sut()->resolve(['uid'], ['uid' => []]),
        );
    }

    public function testUsesFirstValueOfMultiValuedAttribute(): void
    {
        $this->assertSame(
            'first',
            $this->sut()->resolve(['uid'], ['uid' => ['first', 'second']]),
        );
    }
}
