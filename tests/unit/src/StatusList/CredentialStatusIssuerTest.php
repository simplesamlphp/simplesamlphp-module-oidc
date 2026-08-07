<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Contracts\StatusIndexAllocatorInterface;
use SimpleSAML\Module\oidc\StatusList\CredentialStatusIssuer;
use SimpleSAML\Module\oidc\StatusList\SubjectRefHasher;
use SimpleSAML\Module\oidc\StatusList\Values\StatusAllocation;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Helpers as OpenIdHelpers;
use SimpleSAML\OpenID\TokenStatusList;
use SimpleSAML\OpenID\TokenStatusList\Factories\StatusReferenceFactory;
use SimpleSAML\OpenID\TokenStatusList\StatusReference;

#[CoversClass(CredentialStatusIssuer::class)]
class CredentialStatusIssuerTest extends TestCase
{
    protected const string CONFIGURATION_ID = 'TestCredential';

    protected const string CREDENTIAL_ID = 'https://issuer.example.org/vc/abc';

    protected const string USER_IDENTIFIER = 'user@example.org';

    protected const string LIST_URI = 'https://issuer.example.org/module.php/oidc/statuslist/list-1';

    protected MockObject $moduleConfigMock;
    protected MockObject $statusIndexAllocatorMock;
    protected MockObject $subjectRefHasherMock;
    protected MockObject $loggerServiceMock;
    protected TokenStatusList $tokenStatusList;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->statusIndexAllocatorMock = $this->createMock(StatusIndexAllocatorInterface::class);
        $this->subjectRefHasherMock = $this->createMock(SubjectRefHasher::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        // The real reference factory, since the claim it builds is the value under test.
        $this->tokenStatusList = $this->createMock(TokenStatusList::class);
        $this->tokenStatusList->method('statusReferenceFactory')
            ->willReturn(new StatusReferenceFactory(new OpenIdHelpers()));
    }

    protected function sut(): CredentialStatusIssuer
    {
        return new CredentialStatusIssuer(
            $this->moduleConfigMock,
            $this->statusIndexAllocatorMock,
            $this->subjectRefHasherMock,
            $this->tokenStatusList,
            $this->loggerServiceMock,
        );
    }

    /**
     * @throws \SimpleSAML\OpenID\Exceptions\StatusListException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    protected function expectAllocation(int $idx = 5): void
    {
        $this->moduleConfigMock->method('getVciStatusListPoolFor')
            ->willReturn($this->createMock(StatusListPool::class));
        $this->statusIndexAllocatorMock->method('allocateFor')
            ->willReturn(new StatusAllocation('list-1', new StatusReference(self::LIST_URI, $idx)));
    }

    /**
     * @throws \Exception
     */
    public function testBuildsTheClaimFromTheAllocation(): void
    {
        $this->expectAllocation(7);

        $claim = $this->sut()->issueFor(self::CONFIGURATION_ID, self::CREDENTIAL_ID, self::USER_IDENTIFIER);

        $this->assertSame(
            [
                ClaimsEnum::Status->value => [
                    ClaimsEnum::StatusList->value => [
                        ClaimsEnum::Idx->value => 7,
                        ClaimsEnum::Uri->value => self::LIST_URI,
                    ],
                ],
            ],
            $claim?->jsonSerialize(),
        );
    }

    /**
     * A configuration which belongs to no pool was never set up to be revocable, so its credentials
     * are issued exactly as they were before.
     *
     * @throws \Exception
     */
    public function testIssuesNoClaimForAConfigurationWithoutAPool(): void
    {
        $this->moduleConfigMock->method('getVciStatusListPoolFor')->willReturn(null);
        $this->statusIndexAllocatorMock->expects($this->never())->method('allocateFor');

        $this->assertNull(
            $this->sut()->issueFor(self::CONFIGURATION_ID, self::CREDENTIAL_ID, self::USER_IDENTIFIER),
        );
    }

    /**
     * Swallowing this would produce a credential which can never be withdrawn, with nothing on it to
     * say that it is the exception.
     *
     * @throws \Exception
     */
    public function testRaisesAFailureToAllocateRatherThanIssuingWithoutAClaim(): void
    {
        $this->moduleConfigMock->method('getVciStatusListPoolFor')
            ->willReturn($this->createMock(StatusListPool::class));
        $this->statusIndexAllocatorMock->method('allocateFor')
            ->willThrowException(new StatusListException('no list available'));

        $this->expectException(StatusListException::class);

        $this->sut()->issueFor(self::CONFIGURATION_ID, self::CREDENTIAL_ID, self::USER_IDENTIFIER);
    }

    /**
     * The user identifier itself never reaches storage: what is recorded is a keyed hash of it.
     *
     * @throws \Exception
     */
    public function testStoresAHashOfTheUserIdentifierRatherThanTheIdentifier(): void
    {
        $this->moduleConfigMock->method('getVciStatusListPoolFor')
            ->willReturn($this->createMock(StatusListPool::class));
        $this->subjectRefHasherMock->expects($this->once())
            ->method('hash')
            ->with(self::USER_IDENTIFIER)
            ->willReturn('hashed-subject');

        $expiresAt = new DateTimeImmutable('+30 days');

        $this->statusIndexAllocatorMock->expects($this->once())
            ->method('allocateFor')
            ->with(
                $this->anything(),
                self::CREDENTIAL_ID,
                self::CONFIGURATION_ID,
                'hashed-subject',
                $expiresAt,
            )
            ->willReturn(new StatusAllocation('list-1', new StatusReference(self::LIST_URI, 1)));

        $this->sut()->issueFor(
            self::CONFIGURATION_ID,
            self::CREDENTIAL_ID,
            self::USER_IDENTIFIER,
            $expiresAt,
        );
    }
}
