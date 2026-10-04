<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use DateInterval;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
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
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

#[CoversClass(IssuerStateRepository::class)]
#[UsesClass(IssuerStateEntity::class)]
#[UsesClass(IssuerStateEntityFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class IssuerStateRepositoryTest extends TestCase
{
    use LaggingSecondaryTestTrait;


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


    /**
     * What the offer offered is what a request following it may ask for, so it is stored with the state, and
     * an update keeps it as the entity holds it.
     */
    public function testStoresAndUpdatesTheOfferedConfigurations(): void
    {
        $entity = $this->entityFactory->buildNew(credentialConfigurationIds: ['UniversityDegreeCredential']);

        $this->repository->persist($entity);

        $this->assertSame(
            ['UniversityDegreeCredential'],
            $this->repository->find($entity->getValue())?->getCredentialConfigurationIds(),
        );

        $this->repository->update($this->entityFactory->fromData(
            $entity->getValue(),
            $entity->getCreatedAt(),
            $entity->getExpirestAt(),
            false,
            ['UniversityDegreeCredential', 'ResearchAndScholarshipCredentialDcSdJwt'],
        ));

        $this->assertSame(
            ['UniversityDegreeCredential', 'ResearchAndScholarshipCredentialDcSdJwt'],
            $this->repository->find($entity->getValue())?->getCredentialConfigurationIds(),
        );
    }


    public function testFindReturnsNullForUnknownValue(): void
    {
        $this->assertNull($this->repository->find('unknown-issuer-state-value'));
    }


    /**
     * The PAR and authorization endpoints look an issuer state up moments after the Credential Offer carrying it
     * was created, before a secondary may have it.
     */
    public function testFindsAJustOfferedIssuerStateBeforeASecondaryHasIt(): void
    {
        $repository = new IssuerStateRepository(
            $this->moduleConfigMock,
            $this->databaseWithALaggingSecondary(),
            null,
            $this->entityFactory,
            $this->helpers,
        );
        $entity = $this->entityFactory->buildNew();
        $repository->persist($entity);

        $this->assertSame($entity->getValue(), $repository->findValid($entity->getValue())?->getValue());
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


    /**
     * An offer is redeemed once: the first consume spends the state, and every later one is refused.
     */
    public function testConsumeSpendsAValidIssuerStateOnce(): void
    {
        $entity = $this->entityFactory->buildNew();
        $this->repository->persist($entity);

        $this->assertTrue($this->repository->consume($entity->getValue()));
        $this->assertFalse($this->repository->consume($entity->getValue()));

        $foundEntity = $this->repository->find($entity->getValue());
        $this->assertInstanceOf(IssuerStateEntity::class, $foundEntity);
        $this->assertTrue($foundEntity->isRevoked());
        $this->assertNull($this->repository->findValid($entity->getValue()));
    }


    /**
     * An offer which expired before it was redeemed can not be redeemed any more, and is left as it was.
     */
    public function testConsumeRefusesAnExpiredIssuerState(): void
    {
        $createdAt = $this->helpers->dateTime()->getUtc()->sub(new DateInterval('PT10M'));
        $entity = $this->entityFactory->buildNew(
            null,
            $createdAt,
            $createdAt->add(new DateInterval('PT5M')),
        );
        $this->repository->persist($entity);

        $this->assertFalse($this->repository->consume($entity->getValue()));

        $foundEntity = $this->repository->find($entity->getValue());
        $this->assertInstanceOf(IssuerStateEntity::class, $foundEntity);
        $this->assertFalse($foundEntity->isRevoked());
    }


    /**
     * A state spent for a token which was then not issued is given back, and can be redeemed again.
     */
    public function testReleaseGivesBackASpentIssuerState(): void
    {
        $entity = $this->entityFactory->buildNew();
        $this->repository->persist($entity);
        $this->assertTrue($this->repository->consume($entity->getValue()));

        $this->repository->release($entity->getValue());

        $this->assertInstanceOf(IssuerStateEntity::class, $this->repository->findValid($entity->getValue()));
        $this->assertTrue($this->repository->consume($entity->getValue()));
    }


    public function testReleaseDropsTheCachedIssuerState(): void
    {
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->expects($this->once())
            ->method('delete')
            ->with('phpunit_oidc_vci_issuer_state_some-issuer-state');

        $repository = new IssuerStateRepository(
            $this->moduleConfigMock,
            Database::getInstance(),
            $protocolCacheMock,
            $this->entityFactory,
            $this->helpers,
        );

        $repository->release('some-issuer-state');
    }


    public function testConsumeRefusesAnUnknownIssuerState(): void
    {
        $this->assertFalse($this->repository->consume('unknown-issuer-state-value'));
    }


    /**
     * The database decides whether a state was spent; a cached copy read before the consume would still say
     * it is valid, so the consume drops it.
     */
    public function testConsumeDropsTheCachedIssuerState(): void
    {
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->expects($this->once())
            ->method('delete')
            ->with('phpunit_oidc_vci_issuer_state_some-issuer-state');

        $repository = new IssuerStateRepository(
            $this->moduleConfigMock,
            Database::getInstance(),
            $protocolCacheMock,
            $this->entityFactory,
            $this->helpers,
        );

        $this->assertFalse($repository->consume('some-issuer-state'));
    }


    /**
     * Only expired states go. A spent one stays until it expires, so that a redemption whose tokens could not
     * be issued can still give it back.
     */
    public function testRemoveExpiredKeepsSpentStatesUntilTheyExpire(): void
    {
        $validEntity = $this->entityFactory->buildNew();
        $this->repository->persist($validEntity);

        $spentEntity = $this->entityFactory->buildNew();
        $this->repository->persist($spentEntity);
        $this->repository->consume($spentEntity->getValue());

        $createdAt = $this->helpers->dateTime()->getUtc()->sub(new DateInterval('PT10M'));
        $expiredEntity = $this->entityFactory->buildNew(
            null,
            $createdAt,
            $createdAt->add(new DateInterval('PT5M')),
        );
        $this->repository->persist($expiredEntity);

        $this->repository->removeExpired();

        $this->assertInstanceOf(IssuerStateEntity::class, $this->repository->find($validEntity->getValue()));
        $this->assertInstanceOf(IssuerStateEntity::class, $this->repository->find($spentEntity->getValue()));
        $this->assertNull($this->repository->find($expiredEntity->getValue()));
    }


    /**
     * The cleanup may run between a redemption spending a state and giving it back after its tokens could not
     * be issued. The state is still there to give back.
     */
    public function testAStateSpentBeforeTheCleanupCanStillBeGivenBack(): void
    {
        $entity = $this->entityFactory->buildNew();
        $this->repository->persist($entity);
        $this->assertTrue($this->repository->consume($entity->getValue()));

        $this->repository->removeExpired();
        $this->repository->release($entity->getValue());

        $this->assertInstanceOf(IssuerStateEntity::class, $this->repository->findValid($entity->getValue()));
    }
}
