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
use SimpleSAML\Module\oidc\Entities\PushedAuthorizationRequestEntity;
use SimpleSAML\Module\oidc\Factories\Entities\PushedAuthorizationRequestEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

#[CoversClass(PushedAuthorizationRequestRepository::class)]
#[UsesClass(PushedAuthorizationRequestEntity::class)]
#[UsesClass(PushedAuthorizationRequestEntityFactory::class)]
class PushedAuthorizationRequestRepositoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected Helpers $helpers;
    protected PushedAuthorizationRequestEntityFactory $entityFactory;
    protected PushedAuthorizationRequestRepository $repository;

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
        $this->moduleConfigMock->method('getParRequestUriTtl')->willReturn(new DateInterval('PT5M'));
        $this->helpers = new Helpers();
        $this->entityFactory = new PushedAuthorizationRequestEntityFactory(
            $this->moduleConfigMock,
            $this->helpers,
        );

        $this->repository = new PushedAuthorizationRequestRepository(
            $this->moduleConfigMock,
            Database::getInstance(),
            null,
            $this->entityFactory,
            $this->helpers,
        );
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_par', $this->repository->getTableName());
    }

    public function testCanPersistAndFind(): void
    {
        $parameters = ['client_id' => 'client123', 'response_type' => 'code'];
        $entity = $this->entityFactory->buildNew('client123', $parameters);

        $this->repository->persist($entity);

        $foundEntity = $this->repository->find($entity->getRequestUri());

        $this->assertInstanceOf(PushedAuthorizationRequestEntity::class, $foundEntity);
        $this->assertSame($entity->getRequestUri(), $foundEntity->getRequestUri());
        $this->assertSame('client123', $foundEntity->getClientId());
        $this->assertSame($parameters, $foundEntity->getParameters());
        $this->assertSame(
            $entity->getExpiresAt()->getTimestamp(),
            $foundEntity->getExpiresAt()->getTimestamp(),
        );
        $this->assertFalse($foundEntity->isConsumed());
    }

    public function testFindReturnsNullForUnknownRequestUri(): void
    {
        $this->assertNull(
            $this->repository->find(PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX . 'unknown'),
        );
    }

    public function testFindValidReturnsEntityForValidRequestUri(): void
    {
        $entity = $this->entityFactory->buildNew('client123', []);
        $this->repository->persist($entity);

        $this->assertInstanceOf(
            PushedAuthorizationRequestEntity::class,
            $this->repository->findValid($entity->getRequestUri()),
        );
    }

    public function testFindValidReturnsNullForExpiredRequestUri(): void
    {
        $entity = $this->entityFactory->buildNew(
            'client123',
            [],
            $this->helpers->dateTime()->getUtc()->sub(new DateInterval('PT1M')),
        );
        $this->repository->persist($entity);

        $this->assertNull($this->repository->findValid($entity->getRequestUri()));
    }

    public function testFindValidReturnsNullForConsumedRequestUri(): void
    {
        $entity = $this->entityFactory->buildNew('client123', []);
        $this->repository->persist($entity);

        $this->assertTrue($this->repository->consume($entity->getRequestUri()));

        $this->assertNull($this->repository->findValid($entity->getRequestUri()));
    }

    public function testConsumeReturnsTrueOnlyOnce(): void
    {
        $entity = $this->entityFactory->buildNew('client123', []);
        $this->repository->persist($entity);

        $this->assertTrue($this->repository->consume($entity->getRequestUri()));
        // Already consumed, so it can act as an atomic replay guard.
        $this->assertFalse($this->repository->consume($entity->getRequestUri()));
    }

    public function testConsumeReturnsFalseForUnknownRequestUri(): void
    {
        $this->assertFalse(
            $this->repository->consume(PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX . 'unknown'),
        );
    }

    public function testCanRemoveExpired(): void
    {
        $expiredEntity = $this->entityFactory->buildNew(
            'client123',
            [],
            $this->helpers->dateTime()->getUtc()->sub(new DateInterval('PT1M')),
        );
        $this->repository->persist($expiredEntity);
        $validEntity = $this->entityFactory->buildNew('client123', []);
        $this->repository->persist($validEntity);

        $this->repository->removeExpired();

        $this->assertNull($this->repository->find($expiredEntity->getRequestUri()));
        $this->assertInstanceOf(
            PushedAuthorizationRequestEntity::class,
            $this->repository->find($validEntity->getRequestUri()),
        );
    }
}
