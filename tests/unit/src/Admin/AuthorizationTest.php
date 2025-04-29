<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Utils\Auth;

#[CoversClass(Authorization::class)]
class AuthorizationTest extends TestCase
{
    protected MockObject $sspBridgeMock;
    protected MockObject $sspBridgeUtilsMock;
    protected MockObject $sspBridgeUtilsAuthMock;
    protected MockObject $authContextServiceMock;

    protected function setUp(): void
    {
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->sspBridgeUtilsMock = $this->createMock(Utils::class);
        $this->sspBridgeMock->method('utils')->willReturn($this->sspBridgeUtilsMock);
        $this->sspBridgeUtilsAuthMock = $this->createMock(Auth::class);
        $this->sspBridgeUtilsMock->method('auth')->willReturn($this->sspBridgeUtilsAuthMock);

        $this->authContextServiceMock = $this->createMock(AuthContextService::class);
    }

    protected function sut(
        ?SspBridge $sspBridge = null,
        ?AuthContextService $authContextService = null,
    ): Authorization {
        $sspBridge ??= $this->sspBridgeMock;
        $authContextService ??= $this->authContextServiceMock;

        return new Authorization($sspBridge, $authContextService);
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(Authorization::class, $this->sut());
    }

    public function testCanCheckIsAdmin(): void
    {
        $this->assertFalse($this->sut()->isAdmin());
        $this->sspBridgeUtilsAuthMock->method('isAdmin')->willReturn(true);
        $this->assertTrue($this->sut()->isAdmin());
    }

    public function testCanRequireAdmin(): void
    {
        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('admin');

        $this->sspBridgeUtilsAuthMock->method('isAdmin')->willReturn(false);

        $this->sut()->requireAdmin();
    }

    public function testCanForceRequireAdmin(): void
    {
        $this->sspBridgeUtilsAuthMock->expects($this->once())->method('requireAdmin');
        $this->sspBridgeUtilsAuthMock->expects($this->once())->method('isAdmin')->willReturn(true);

        $this->sut()->requireAdmin(true);
    }

    public function testThrowsOnForceRequireAdminError(): void
    {
        $this->sspBridgeUtilsAuthMock->expects($this->once())->method('requireAdmin')
        ->willThrowException(new Exception('error'));

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('admin');

        $this->sut()->requireAdmin(true);
    }

    public function testRequireAdminOrUserWithPermissionReturnsIfAdmin(): void
    {
        $this->sspBridgeUtilsAuthMock->expects($this->once())->method('isAdmin')->willReturn(true);
        $this->authContextServiceMock->expects($this->never())->method('requirePermission');

        $this->sut()->requireAdminOrUserWithPermission('permission');
    }

    public function testRequireAdminOrUserWithPermissionReturnsIfUser(): void
    {
        $this->sspBridgeUtilsAuthMock->expects($this->atLeastOnce())->method('isAdmin')
            ->willReturnOnConsecutiveCalls(
                false,
                true, // After requireAdmin called, isAdmin will return true
            );
        $this->sspBridgeUtilsAuthMock->expects($this->once())->method('requireAdmin');
        $this->authContextServiceMock->expects($this->once())->method('requirePermission');

        $this->sut()->requireAdminOrUserWithPermission('permission');
    }

    public function testRequireUserWithPermissionThrowsIfUserNotAuthorized(): void
    {
        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('access required');

        $this->sspBridgeUtilsAuthMock->expects($this->atLeastOnce())->method('isAdmin')->willReturn(false);
        $this->authContextServiceMock->expects($this->once())->method('requirePermission')
            ->willThrowException(new Exception('error'));

        $this->sut()->requireAdminOrUserWithPermission('permission');
    }

    public function testCanGetUserId(): void
    {
        $this->authContextServiceMock->expects($this->once())->method('getAuthUserId')->willReturn('id');

        $this->assertSame('id', $this->sut()->getUserId());
    }
}
