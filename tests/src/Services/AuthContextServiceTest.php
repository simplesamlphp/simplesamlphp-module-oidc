<?php

namespace SimpleSAML\Test\Module\oidc\Services;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Configuration;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Services\AuthContextService;

/**
 * @covers \SimpleSAML\Module\oidc\Services\AuthContextService
 */
class AuthContextServiceTest extends TestCase
{
    public const AUTHORIZED_USER = [
        'idAttribute' => ['myUsername'],
        'someEntitlement' => ['val1', 'val2', 'val3']
    ];
    protected Configuration $permissions;
    protected \PHPUnit\Framework\MockObject\MockObject $oidcConfigurationMock;
    protected \PHPUnit\Framework\MockObject\MockObject $moduleConfigMock;
    protected \PHPUnit\Framework\MockObject\MockObject $authSimpleService;
    protected \PHPUnit\Framework\MockObject\MockObject $authSimpleFactory;

    protected function setUp(): void
    {
        $this->permissions = Configuration::loadFromArray(
            [
                // Attribute to inspect to determine user's permissions
                'attribute' => 'someEntitlement',
                // Entitlements allow for registering, editing, delete a client. OIDC clients are owned by the creator
                'client' => ['val2'],
            ]
        );

        $this->oidcConfigurationMock = $this->createMock(Configuration::class);

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getOpenIDConnectConfiguration')
            ->willReturn($this->oidcConfigurationMock);

        $this->authSimpleService = $this->createMock(Simple::class);

        $this->authSimpleFactory = $this->createMock(AuthSimpleFactory::class);
        $this->authSimpleFactory->method('getDefaultAuthSource')->willReturn($this->authSimpleService);
    }

    protected function prepareMockedInstance(): AuthContextService
    {
        return new AuthContextService(
            $this->moduleConfigMock,
            $this->authSimpleFactory
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AuthContextService::class,
            $this->prepareMockedInstance()
        );
    }

    public function testItReturnsUsername(): void
    {
        $this->oidcConfigurationMock->method('getString')
            ->with('useridattr')
            ->willReturn('idAttribute');
        $this->authSimpleService->method('getAttributes')->willReturn(self::AUTHORIZED_USER);

        $this->assertSame(
            $this->prepareMockedInstance()->getAuthUserId(),
            'myUsername'
        );
    }

    public function testItThrowsWhenNoUsername(): void
    {
        $this->oidcConfigurationMock->method('getOptionalConfigItem')
            ->with('permissions', null)
            ->willReturn($this->permissions);
        $this->oidcConfigurationMock->method('getString')
            ->with('useridattr')
            ->willReturn('attributeNotSet');
        $this->authSimpleService->method('getAttributes')->willReturn(self::AUTHORIZED_USER);

        $this->expectException(Exception::class);
        $this->prepareMockedInstance()->getAuthUserId();
    }

    public function testPermissionsOk(): void
    {
        $this->oidcConfigurationMock->method('getOptionalConfigItem')
            ->with('permissions', null)
            ->willReturn($this->permissions);
        $this->authSimpleService->method('getAttributes')->willReturn(self::AUTHORIZED_USER);

        $this->prepareMockedInstance()->requirePermission('client');
        $this->expectNotToPerformAssertions();
    }

    public function testItThrowsIfNotAuthorizedForPermission(): void
    {
        $this->oidcConfigurationMock->method('getOptionalConfigItem')
            ->with('permissions', null)
            ->willReturn($this->permissions);
        $this->expectException(\RuntimeException::class);
        $this->prepareMockedInstance()->requirePermission('no-match');
    }

    public function testItThrowsForWrongEntitlements(): void
    {
        $this->oidcConfigurationMock->method('getOptionalConfigItem')
            ->with('permissions', null)
            ->willReturn($this->permissions);
        $this->authSimpleService->method('getAttributes')
            ->willReturn(
                [
                    'idAttribute' => ['myUsername'],
                    'someEntitlement' =>  ['otherEntitlement']
                ]
            );

        $this->expectException(\RuntimeException::class);
        $this->prepareMockedInstance()->requirePermission('client');
    }

    public function testItThrowsForNotHavingEntitlementAttribute(): void
    {
        $this->oidcConfigurationMock->method('getOptionalConfigItem')
            ->with('permissions', null)
            ->willReturn($this->permissions);
        $this->authSimpleService->method('getAttributes')
            ->willReturn(
                [
                    'idAttribute' => ['myUsername'],
                ]
            );

        $this->expectException(\RuntimeException::class);
        $this->prepareMockedInstance()->requirePermission('client');
    }

    public function testThrowsForNotHavingEnabledPermissions(): void
    {
        $this->oidcConfigurationMock->method('getOptionalConfigItem')
            ->with('permissions', null)
            ->willReturn(Configuration::loadFromArray([]));

        $this->expectException(\RuntimeException::class);
        $this->prepareMockedInstance()->requirePermission('client');
    }
}
