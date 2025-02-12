<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Configuration;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Utils\Attributes;

/**
 * @covers \SimpleSAML\Module\oidc\Services\AuthContextService
 */
class AuthContextServiceTest extends TestCase
{
    final public const AUTHORIZED_USER = [
        'idAttribute' => ['myUsername'],
        'someEntitlement' => ['val1', 'val2', 'val3'],
    ];
    protected Configuration $permissions;
    protected MockObject $oidcConfigurationMock;
    protected MockObject $moduleConfigMock;
    protected MockObject $authSimpleService;
    protected MockObject $authSimpleFactory;
    protected MockObject $sspBridgeMock;
    protected MockObject $sspBridgeUtilsMock;
    protected MockObject $sspBridgeUtilsAttributesMock;

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
            ],
        );

        $this->oidcConfigurationMock = $this->createMock(Configuration::class);

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('config')->willReturn($this->oidcConfigurationMock);

        $this->authSimpleService = $this->createMock(Simple::class);

        $this->authSimpleFactory = $this->createMock(AuthSimpleFactory::class);
        $this->authSimpleFactory->method('getDefaultAuthSource')->willReturn($this->authSimpleService);

        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->sspBridgeUtilsMock = $this->createMock(SspBridge\Utils::class);
        $this->sspBridgeMock->method('utils')->willReturn($this->sspBridgeUtilsMock);
        $this->sspBridgeUtilsAttributesMock = $this->createMock(Attributes::class);
        $this->sspBridgeUtilsMock->method('attributes')->willReturn($this->sspBridgeUtilsAttributesMock);
    }

    protected function sut(
        ?ModuleConfig $moduleConfig = null,
        ?AuthSimpleFactory $authSimpleFactory = null,
        ?SspBridge $sspBridge = null,
    ): AuthContextService {
        $moduleConfig ??= $this->moduleConfigMock;
        $authSimpleFactory ??= $this->authSimpleFactory;
        $sspBridge ??= $this->sspBridgeMock;

        return new AuthContextService(
            $moduleConfig,
            $authSimpleFactory,
            $sspBridge,
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AuthContextService::class,
            $this->sut(),
        );
    }

    /**
     * @throws \Exception
     */
    public function testItReturnsUsername(): void
    {
        $this->moduleConfigMock->method('getUserIdentifierAttribute')->willReturn('idAttribute');
        $this->authSimpleService->method('getAttributes')->willReturn(self::AUTHORIZED_USER);
        $this->sspBridgeUtilsAttributesMock->expects($this->once())->method('getExpectedAttribute')
            ->with(
                self::AUTHORIZED_USER,
                'idAttribute',
            )
            ->willReturn(self::AUTHORIZED_USER['idAttribute'][0]);

        $this->assertSame(
            $this->sut()->getAuthUserId(),
            'myUsername',
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

        $this->sspBridgeUtilsAttributesMock->expects($this->once())->method('getExpectedAttribute')
            ->with(self::AUTHORIZED_USER)
            ->willThrowException(new Exception('error'));

        $this->expectException(Exception::class);
        $this->sut()->getAuthUserId();
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

        $this->sut()->requirePermission('client');
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
        $this->sut()->requirePermission('no-match');
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
                    'someEntitlement' =>  ['otherEntitlement'],
                ],
            );

        $this->expectException(RuntimeException::class);
        $this->sut()->requirePermission('client');
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
                ],
            );

        $this->expectException(RuntimeException::class);
        $this->sut()->requirePermission('client');
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
        $this->sut()->requirePermission('client');
    }
}
