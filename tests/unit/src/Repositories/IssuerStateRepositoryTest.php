<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use DateInterval;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Entities\IssuerStateEntity;
use SimpleSAML\Module\oidc\Factories\Entities\IssuerStateEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

#[CoversClass(IssuerStateRepository::class)]
#[UsesClass(IssuerStateEntity::class)]
#[UsesClass(IssuerStateEntityFactory::class)]
class IssuerStateRepositoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected Helpers $helpers;
    protected IssuerStateEntityFactory $entityFactory;
    protected IssuerStateRepository $repository;

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
        $this->moduleConfigMock->method('getVciIssuerStateDuration')->willReturn(new DateInterval('PT5M'));
        $this->helpers = new Helpers();
        $this->entityFactory = new IssuerStateEntityFactory(
            $this->moduleConfigMock,
            $this->helpers,
        );

        $this->repository = new IssuerStateRepository(
            $this->moduleConfigMock,
            Database::getInstance(),
            null,
            $this->entityFactory,
            $this->helpers,
        );
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_vci_issuer_state', $this->repository->getTableName());
    }

    public function testGetCacheKeyIsTablePrefixed(): void
    {
        $this->assertSame(
            'phpunit_oidc_vci_issuer_state_sample',
            $this->repository->getCacheKey('sample'),
        );
    }

    public function testCanPersistAndFind(): void
    {
        $entity = $this->entityFactory->buildNew();

        $this->repository->persist($entity);

        $foundEntity = $this->repository->find($entity->getValue());

        $this->assertInstanceOf(IssuerStateEntity::class, $foundEntity);
        $this->assertSame($entity->getValue(), $foundEntity->getValue());
        $this->assertSame(
            $entity->getExpirestAt()->getTimestamp(),
            $foundEntity->getExpirestAt()->getTimestamp(),
        );
        $this->assertFalse($foundEntity->isRevoked());
    }

    public function testFindReturnsNullForUnknownValue(): void
    {
        $this->assertNull($this->repository->find('unknown-issuer-state-value'));
    }

    public function testFindValidReturnsEntityForValidValue(): void
    {
        $entity = $this->entityFactory->buildNew();
        $this->repository->persist($entity);

        $this->assertInstanceOf(
            IssuerStateEntity::class,
            $this->repository->findValid($entity->getValue()),
        );
    }

    public function testFindValidReturnsNullForExpiredValue(): void
    {
        $createdAt = $this->helpers->dateTime()->getUtc()->sub(new DateInterval('PT10M'));
        $entity = $this->entityFactory->buildNew(
            null,
            $createdAt,
            $createdAt->add(new DateInterval('PT5M')),
        );
        $this->repository->persist($entity);

        $this->assertInstanceOf(IssuerStateEntity::class, $this->repository->find($entity->getValue()));
        $this->assertNull($this->repository->findValid($entity->getValue()));
    }

    public function testCanRevoke(): void
    {
        $entity = $this->entityFactory->buildNew();
        $this->repository->persist($entity);

        $this->repository->revoke($entity->getValue());

        $foundEntity = $this->repository->find($entity->getValue());
        $this->assertInstanceOf(IssuerStateEntity::class, $foundEntity);
        $this->assertTrue($foundEntity->isRevoked());
        $this->assertNull($this->repository->findValid($entity->getValue()));
    }

    public function testCanRemoveInvalid(): void
    {
        $validEntity = $this->entityFactory->buildNew();
        $this->repository->persist($validEntity);

        $revokedEntity = $this->entityFactory->buildNew();
        $this->repository->persist($revokedEntity);
        $this->repository->revoke($revokedEntity->getValue());

        $createdAt = $this->helpers->dateTime()->getUtc()->sub(new DateInterval('PT10M'));
        $expiredEntity = $this->entityFactory->buildNew(
            null,
            $createdAt,
            $createdAt->add(new DateInterval('PT5M')),
        );
        $this->repository->persist($expiredEntity);

        $this->repository->removeInvalid();

        $this->assertInstanceOf(IssuerStateEntity::class, $this->repository->find($validEntity->getValue()));
        $this->assertNull($this->repository->find($revokedEntity->getValue()));
        $this->assertNull($this->repository->find($expiredEntity->getValue()));
    }
}
