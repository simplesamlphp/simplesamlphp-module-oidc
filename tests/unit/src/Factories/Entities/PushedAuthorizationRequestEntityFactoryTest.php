<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories\Entities;

use DateInterval;
use DateTimeZone;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\PushedAuthorizationRequestEntity;
use SimpleSAML\Module\oidc\Factories\Entities\PushedAuthorizationRequestEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Exceptions\OpenIdException;

#[CoversClass(PushedAuthorizationRequestEntityFactory::class)]
#[UsesClass(PushedAuthorizationRequestEntity::class)]
class PushedAuthorizationRequestEntityFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected Helpers $helpers;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getParRequestUriTtl')->willReturn(new DateInterval('PT5M'));
        $this->helpers = new Helpers();
    }

    protected function sut(): PushedAuthorizationRequestEntityFactory
    {
        return new PushedAuthorizationRequestEntityFactory(
            $this->moduleConfigMock,
            $this->helpers,
        );
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(PushedAuthorizationRequestEntityFactory::class, $this->sut());
    }

    public function testCanBuildNew(): void
    {
        $parameters = ['client_id' => 'client123', 'response_type' => 'code'];

        $entity = $this->sut()->buildNew('client123', $parameters);

        $this->assertStringStartsWith(
            PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX,
            $entity->getRequestUri(),
        );
        // Random part is 32 bytes, hex encoded.
        $this->assertSame(
            strlen(PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX) + 64,
            strlen($entity->getRequestUri()),
        );
        $this->assertSame('client123', $entity->getClientId());
        $this->assertSame($parameters, $entity->getParameters());
        $this->assertFalse($entity->isConsumed());

        $expectedExpiresAt = $this->helpers->dateTime()->getUtc()->add(new DateInterval('PT5M'));
        $this->assertEqualsWithDelta(
            $expectedExpiresAt->getTimestamp(),
            $entity->getExpiresAt()->getTimestamp(),
            5,
        );
    }

    public function testBuildNewGeneratesUniqueRequestUris(): void
    {
        $sut = $this->sut();

        $this->assertNotSame(
            $sut->buildNew('client123', [])->getRequestUri(),
            $sut->buildNew('client123', [])->getRequestUri(),
        );
    }

    public function testCanBuildFromState(): void
    {
        $entity = $this->sut()->fromState([
            'request_uri' => PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX . 'abc123',
            'client_id' => 'client123',
            'parameters' => '{"response_type":"code"}',
            'expires_at' => '2026-01-01 12:00:00',
            'is_consumed' => 0,
        ]);

        $this->assertSame(
            PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX . 'abc123',
            $entity->getRequestUri(),
        );
        $this->assertSame('client123', $entity->getClientId());
        $this->assertSame(['response_type' => 'code'], $entity->getParameters());
        $this->assertFalse($entity->isConsumed());

        // Stored datetimes are interpreted as UTC.
        $this->assertSame(
            '2026-01-01 12:00:00',
            $entity->getExpiresAt()->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
        );
    }

    public function testFromStateThrowsForInvalidState(): void
    {
        $this->expectException(OpenIdException::class);

        $this->sut()->fromState([
            'request_uri' => 123,
            'client_id' => 'client123',
            'parameters' => '{}',
            'expires_at' => '2026-01-01 12:00:00',
        ]);
    }
}
