<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\ClaimSetEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\SubjectResolver;

/**
 * The rule is the one IdTokenBuilder applied on its own before the subject was resolved once at minting: the
 * value the 'sub' translation yields, else the internal user identifier. A real extractor is used so that the
 * tests say what a configured translation table does, not what a mock was told to answer.
 */
#[CoversClass(SubjectResolver::class)]
#[UsesClass(ClaimTranslatorExtractor::class)]
#[UsesClass(ClaimSetEntity::class)]
#[UsesClass(ClaimSetEntityFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class SubjectResolverTest extends TestCase
{
    protected LoggerService&MockObject $loggerServiceMock;


    protected function setUp(): void
    {
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }


    protected function sut(array $translationTable = []): SubjectResolver
    {
        return new SubjectResolver(
            new ClaimTranslatorExtractor(['uid'], new ClaimSetEntityFactory(), [], $translationTable),
            $this->loggerServiceMock,
        );
    }


    protected function user(array $claims, string $identifier = 'internal-id'): UserEntity
    {
        $user = $this->createMock(UserEntity::class);
        $user->method('getIdentifier')->willReturn($identifier);
        $user->method('getClaims')->willReturn($claims);

        return $user;
    }


    /**
     * By default the user identifier attribute heads the 'sub' translation, so the subject is what the internal
     * identifier was made from.
     */
    public function testResolvesTheSubjectFromTheDefaultTranslation(): void
    {
        $this->loggerServiceMock->expects($this->never())->method('warning');

        $this->assertSame('u1', $this->sut()->resolve($this->user(['uid' => ['u1']])));
    }


    public function testResolvesTheSubjectFromAConfiguredTranslation(): void
    {
        $this->loggerServiceMock->expects($this->never())->method('warning');

        $this->assertSame(
            'v1@example.org',
            $this->sut(['sub' => ['voPersonID']])->resolve(
                $this->user(['uid' => ['u1'], 'voPersonID' => ['v1@example.org']]),
            ),
        );
    }


    /**
     * A subject of "0" is valid and must not be mistaken for "no value".
     */
    public function testKeepsAFalsyButValidSubject(): void
    {
        $this->assertSame('0', $this->sut()->resolve($this->user(['uid' => ['0']])));
    }


    /**
     * An emptied translation ('sub' => []) means the internal identifier on purpose, so no warning.
     */
    public function testFallsBackToTheInternalIdentifierSilentlyForAnEmptiedTranslation(): void
    {
        $this->loggerServiceMock->expects($this->never())->method('warning');

        $this->assertSame(
            'internal-id',
            $this->sut(['sub' => []])->resolve($this->user(['uid' => ['u1']])),
        );
    }


    /**
     * A translation with attributes to read which yields nothing is a gap worth telling the operator about:
     * the identifier is used, and the warning names the user, not the attributes.
     */
    public function testFallsBackToTheInternalIdentifierWithAWarningWhenTheTranslationYieldsNothing(): void
    {
        $this->loggerServiceMock->expects($this->once())
            ->method('warning')
            ->with($this->stringContains('yields no value'), ['user_id' => 'internal-id']);

        $this->assertSame(
            'internal-id',
            $this->sut(['sub' => ['voPersonID']])->resolve($this->user(['uid' => ['u1']])),
        );
    }


    /**
     * The extractor's rule for 'sub' holds here as everywhere: a value which is not a non-empty string is an
     * error, not a subject.
     */
    public function testRefusesASubjectWhichIsNotANonEmptyString(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("'sub'");

        $this->sut()->resolve($this->user(['uid' => ['']]));
    }
}
