<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\ModuleConfig;

#[CoversClass(AuthSimpleFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class AuthSimpleFactoryTest extends TestCase
{
    protected const string DEFAULT_AUTH_SOURCE_ID = 'default-sp';

    protected const string CLIENT_AUTH_SOURCE_ID = 'client-sp';


    protected MockObject $moduleConfigMock;

    protected bool $hadRequestUri = false;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getDefaultAuthSourceId')->willReturn(self::DEFAULT_AUTH_SOURCE_ID);

        // Building a `Simple` reaches SimpleSAMLphp's session handling, which reads the request URI. There
        // is no request here, so it is supplied rather than left to warn.
        $this->hadRequestUri = isset($_SERVER['REQUEST_URI']);
        $_SERVER['REQUEST_URI'] ??= '/';
    }


    protected function tearDown(): void
    {
        if (!$this->hadRequestUri) {
            unset($_SERVER['REQUEST_URI']);
        }
    }


    protected function sut(): AuthSimpleFactory
    {
        return new AuthSimpleFactory($this->moduleConfigMock);
    }


    /**
     * Which authentication source a `Simple` was built for, which it offers no accessor for. Reading it
     * back is the only way to tell these apart without loading the source itself, which would need the
     * whole SimpleSAMLphp authentication stack behind it.
     */
    protected function authSourceIdOf(Simple $authSimple): string
    {
        return (string)(new ReflectionProperty(Simple::class, 'authSource'))->getValue($authSimple);
    }


    public function testResolvesTheConfiguredDefaultForAClientWithNoAuthSourceOfItsOwn(): void
    {
        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getAuthSourceId')->willReturn(null);

        $this->assertSame(self::DEFAULT_AUTH_SOURCE_ID, $this->sut()->resolveAuthSourceId($clientMock));
    }


    /**
     * A client which is not this module's own entity has no authentication source to state.
     */
    public function testResolvesTheConfiguredDefaultForAPlainOAuth2Client(): void
    {
        $clientMock = $this->createMock(OAuth2ClientEntityInterface::class);

        $this->assertSame(self::DEFAULT_AUTH_SOURCE_ID, $this->sut()->resolveAuthSourceId($clientMock));
    }


    /**
     * A client may name the authentication source its users are sent to, which is the whole point of the
     * value being stored on the client rather than only in configuration.
     *
     * This was a regression on the version 7 branch, and this test is what would have caught it. When
     * `resolveAuthSourceId()` was widened to accept a plain OAuth2 client, the narrowing added for this
     * module's own entity lost its `return`: the client's authentication source was read and the result
     * discarded, so the configured default was returned whatever the client said. Released 6.4.x
     * resolves it correctly, so shipping it would have moved every client onto the default source
     * without anything saying so.
     */
    public function testUsesTheAuthSourceTheClientNames(): void
    {
        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getAuthSourceId')->willReturn(self::CLIENT_AUTH_SOURCE_ID);

        $this->assertSame(self::CLIENT_AUTH_SOURCE_ID, $this->sut()->resolveAuthSourceId($clientMock));
    }


    /**
     * And the source it names is the one a `Simple` is built for, since that is what `build()` hands to
     * everything which authenticates.
     *
     * @throws \Exception
     */
    public function testBuildsAnAuthSourceForTheClientsOwnSource(): void
    {
        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getAuthSourceId')->willReturn(self::CLIENT_AUTH_SOURCE_ID);

        $this->assertSame(
            self::CLIENT_AUTH_SOURCE_ID,
            $this->authSourceIdOf($this->sut()->build($clientMock)),
        );
    }


    public function testTheDefaultAuthSourceIsTheConfiguredOne(): void
    {
        $this->assertSame(
            self::DEFAULT_AUTH_SOURCE_ID,
            $this->authSourceIdOf($this->sut()->getDefaultAuthSource()),
        );
    }


    public function testBuildsAnAuthSourceForAnyIdItIsGiven(): void
    {
        $this->assertSame(
            'some-other-sp',
            $this->authSourceIdOf($this->sut()->forAuthSourceId('some-other-sp')),
        );
    }
}
