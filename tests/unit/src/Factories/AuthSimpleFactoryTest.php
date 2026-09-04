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
     * Pins current behaviour, which is not what the method sets out to do.
     *
     * `resolveAuthSourceId()` reads the client's own authentication source and then discards the result:
     * the expression on that line is evaluated and assigned to nothing, so the configured default is
     * returned whatever the client says. Every authorization request therefore authenticates against the
     * default source, and the per-client value - stored on the client, editable in the administration
     * interface, and carried through client registration - reaches nothing.
     *
     * Making it take effect is a change in who authenticates where, on deployments which may have set
     * that value years ago and never seen it used, so it is left to the user rather than fixed while
     * writing a test. This test is what will fail when it is fixed, and its name is what says so.
     */
    public function testAClientsOwnAuthSourceIsCurrentlyIgnored(): void
    {
        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getAuthSourceId')->willReturn(self::CLIENT_AUTH_SOURCE_ID);

        $this->assertSame(self::DEFAULT_AUTH_SOURCE_ID, $this->sut()->resolveAuthSourceId($clientMock));
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
