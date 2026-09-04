<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\VciIssuerIdentityRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentity;

#[CoversClass(VciIssuerIdentityRepository::class)]
#[AllowMockObjectsWithoutExpectations]
class VciIssuerIdentityRepositoryTest extends TestCase
{
    protected const string DID_WEB = 'did:web:example.org';


    protected MockObject $moduleConfigMock;

    protected VciIssuerIdentityRepository $repository;


    /**
     * @throws \Exception
     */
    public static function setUpBeforeClass(): void
    {
        $config = [
            'database.dsn' => 'sqlite::memory:',
            'database.username' => null,
            'database.password' => null,
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.secondaries' => [],
        ];

        Configuration::loadFromArray($config, '', 'simplesaml');
        (new DatabaseMigration())->migrate();
    }


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);

        $this->repository = new VciIssuerIdentityRepository(
            $this->moduleConfigMock,
            Database::getInstance(),
            null,
            new Helpers(),
        );

        Database::getInstance()->write('DELETE FROM ' . $this->repository->getTableName());
    }


    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_vci_issuer_identity', $this->repository->getTableName());
    }


    public function testRecordsNothingUntilAnIdentityIsUsed(): void
    {
        $this->assertSame([], $this->repository->getAllUsed());
    }


    public function testRecordsTheIdentityAndTheModeItCameFrom(): void
    {
        $this->repository->recordUsage($this->identity(VciIssuerIdentifierModeEnum::DidWeb, self::DID_WEB));

        $this->assertSame(
            [self::DID_WEB => VciIssuerIdentifierModeEnum::DidWeb->value],
            $this->repository->getAllUsed(),
        );
    }


    /**
     * Recorded once, however many credentials are issued under it.
     */
    public function testRecordingTheSameIdentityAgainChangesNothing(): void
    {
        $identity = $this->identity(VciIssuerIdentifierModeEnum::DidWeb, self::DID_WEB);

        $this->repository->recordUsage($identity);
        $this->repository->recordUsage($identity);
        $this->repository->recordUsage($identity);

        $this->assertCount(1, $this->repository->getAllUsed());
    }


    /**
     * The whole point of keeping a set rather than the first identity: a deployment which moved away
     * and back would otherwise compare equal to what is stored and report nothing, while credentials
     * issued in between stay unverifiable.
     */
    public function testKeepsEveryIdentityEverUsed(): void
    {
        $this->repository->recordUsage($this->identity(VciIssuerIdentifierModeEnum::DidWeb, self::DID_WEB));
        $this->repository->recordUsage($this->identity(VciIssuerIdentifierModeEnum::DidJwk, 'did:jwk:first'));
        $this->repository->recordUsage($this->identity(VciIssuerIdentifierModeEnum::DidWeb, 'did:web:other.org'));
        $this->repository->recordUsage($this->identity(VciIssuerIdentifierModeEnum::DidWeb, self::DID_WEB));

        $this->assertSame(
            [
                self::DID_WEB => VciIssuerIdentifierModeEnum::DidWeb->value,
                'did:jwk:first' => VciIssuerIdentifierModeEnum::DidJwk->value,
                'did:web:other.org' => VciIssuerIdentifierModeEnum::DidWeb->value,
            ],
            $this->repository->getAllUsed(),
        );
    }


    /**
     * A did:jwk carrying an RSA key runs past what MySQL will index, which is why the key is a hash of
     * the identifier rather than the identifier itself.
     */
    public function testRecordsAnIdentifierTooLongToBeIndexed(): void
    {
        $identifier = 'did:jwk:' . str_repeat('a', 4000);

        $this->repository->recordUsage($this->identity(VciIssuerIdentifierModeEnum::DidJwk, $identifier));

        $this->assertSame(
            [$identifier => VciIssuerIdentifierModeEnum::DidJwk->value],
            $this->repository->getAllUsed(),
        );
    }


    protected function identity(VciIssuerIdentifierModeEnum $mode, string $issuer): VciIssuerIdentity
    {
        return new VciIssuerIdentity($mode, $issuer, $issuer . '#0');
    }
}
