<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Services;

use PHPUnit\Framework\MockObject\MockObject;
use RuntimeException;
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
    final public const AUTHORIZED_USER = [
        'idAttribute' => ['myUsername'],
        'someEntitlement' => ['val1', 'val2', 'val3']
    ];
    protected Configuration $permissions;
    protected MockObject $oidcConfigurationMock;
    protected MockObject $moduleConfigMock;
    protected MockObject $authSimpleService;
    protected MockObject $authSimpleFactory;

    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
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
        $this->moduleConfigMock->method('config')
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

    /**
     * @throws Exception
     */
    public function testItReturnsUsername(): void
    {
        $this->oidcConfigurationMock->method('getString')
            ->with(ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE)
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
            ->with(ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS, null)
            ->willReturn($this->permissions);
        $this->oidcConfigurationMock->method('getString')
            ->with(ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE)
            ->willReturn('attributeNotSet');
        $this->authSimpleService->method('getAttributes')->willReturn(self::AUTHORIZED_USER);

        $this->expectException(Exception::class);
        $this->prepareMockedInstance()->getAuthUserId();
    }

    /**
     * @throws \Exception
     */
    public function testPermissionsOk(): void
    {
        $this->oidcConfigurationMock->method('getOptionalConfigItem')
            ->with(ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS, null)
            ->willReturn($this->permissions);
        $this->authSimpleService->method('getAttributes')->willReturn(self::AUTHORIZED_USER);

        $this->prepareMockedInstance()->requirePermission('client');
        $this->expectNotToPerformAssertions();
    }

    /**
     * @throws \Exception
     */
    public function testItThrowsIfNotAuthorizedForPermission(): void
    {
        $this->oidcConfigurationMock->method('getOptionalConfigItem')
            ->with(ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS, null)
            ->willReturn($this->permissions);
        $this->expectException(RuntimeException::class);
        $this->prepareMockedInstance()->requirePermission('no-match');
    }

    /**
     * @throws \Exception
     */
    public function testItThrowsForWrongEntitlements(): void
    {
        $this->oidcConfigurationMock->method('getOptionalConfigItem')
            ->with(ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS, null)
            ->willReturn($this->permissions);
        $this->authSimpleService->method('getAttributes')
            ->willReturn(
                [
                    'idAttribute' => ['myUsername'],
                    'someEntitlement' =>  ['otherEntitlement']
                ]
            );

        $this->expectException(RuntimeException::class);
        $this->prepareMockedInstance()->requirePermission('client');
    }

    /**
     * @throws \Exception
     */
    public function testItThrowsForNotHavingEntitlementAttribute(): void
    {
        $this->oidcConfigurationMock->method('getOptionalConfigItem')
            ->with(ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS, null)
            ->willReturn($this->permissions);
        $this->authSimpleService->method('getAttributes')
            ->willReturn(
                [
                    'idAttribute' => ['myUsername'],
                ]
            );

        $this->expectException(RuntimeException::class);
        $this->prepareMockedInstance()->requirePermission('client');
    }

    /**
     * @throws \Exception
     */
    public function testThrowsForNotHavingEnabledPermissions(): void
    {
        $this->oidcConfigurationMock->method('getOptionalConfigItem')
            ->with(ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS, null)
            ->willReturn(Configuration::loadFromArray([]));

        $this->expectException(RuntimeException::class);
        $this->prepareMockedInstance()->requirePermission('client');
    }
}
