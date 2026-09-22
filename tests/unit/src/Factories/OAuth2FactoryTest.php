<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use DateInterval;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Factories\OAuth2Factory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Decorators\DateIntervalDecorator;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\SupportedSerializers;

/**
 * The factory behind the library's OAuth2 service.
 *
 * `routing/services/services.yml` names `build` as the factory of the `SimpleSAML\OpenID\OAuth2` service,
 * which the access token entity mints its JWT through (RFC 9068). What the factory decides is what the
 * library runs with: the configured signature algorithms, serializers and timestamp validation leeway --
 * the same three the Jws service gets, so a token minted here parses there. The tests read them back
 * through the accessors.
 */
#[CoversClass(OAuth2Factory::class)]
#[AllowMockObjectsWithoutExpectations]
class OAuth2FactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected SupportedAlgorithms $supportedAlgorithms;

    protected SupportedSerializers $supportedSerializers;

    protected DateInterval $timestampValidationLeeway;


    protected function setUp(): void
    {
        $this->supportedAlgorithms = new SupportedAlgorithms();
        $this->supportedSerializers = new SupportedSerializers();
        $this->timestampValidationLeeway = new DateInterval('PT3M');

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getSupportedAlgorithms')->willReturn($this->supportedAlgorithms);
        $this->moduleConfigMock->method('getSupportedSerializers')->willReturn($this->supportedSerializers);
        $this->moduleConfigMock->method('getTimestampValidationLeeway')
            ->willReturn($this->timestampValidationLeeway);
    }


    protected function sut(): OAuth2Factory
    {
        return new OAuth2Factory($this->moduleConfigMock);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(OAuth2Factory::class, $this->sut());
    }


    /**
     * The configured algorithms, serializers and leeway are handed over as the very objects, the leeway
     * wrapped in the library's decorator.
     */
    public function testBuildsTheOAuth2AroundTheConfiguredAlgorithmsSerializersAndLeeway(): void
    {
        $oAuth2 = $this->sut()->build();

        $this->assertSame($this->supportedAlgorithms, $oAuth2->supportedAlgorithms());
        $this->assertSame($this->supportedSerializers, $oAuth2->supportedSerializers());
        $leewayDecorator = $oAuth2->timestampValidationLeewayDecorator();
        $this->assertInstanceOf(DateIntervalDecorator::class, $leewayDecorator);
        $this->assertSame($this->timestampValidationLeeway, $leewayDecorator->dateInterval);
    }
}
