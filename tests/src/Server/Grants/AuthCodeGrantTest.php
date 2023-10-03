<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\Grants;

use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\Stub;
use DateInterval;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AuthCodeRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;

/**
 * @covers \SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant
 */
class AuthCodeGrantTest extends TestCase
{
    protected Stub $authCodeRepositoryStub;
    protected Stub $accessTokenRepositoryStub;
    protected Stub $refreshTokenRepositoryStub;
    protected DateInterval $authCodeTtl;
    protected Stub $requestRulesManagerStub;
    protected Stub $moduleConfigStub;

    /**
     * @throws Exception
     */
    protected function setUp(): void
    {
        $this->authCodeRepositoryStub = $this->createStub(AuthCodeRepositoryInterface::class);
        $this->accessTokenRepositoryStub = $this->createStub(AccessTokenRepositoryInterface::class);
        $this->refreshTokenRepositoryStub = $this->createStub(RefreshTokenRepositoryInterface::class);
        $this->authCodeTtl = new DateInterval('PT1M');
        $this->requestRulesManagerStub = $this->createStub(RequestRulesManager::class);
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
    }

    /**
     * @throws \Exception
     */
    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(
            AuthCodeGrant::class,
            new AuthCodeGrant(
                $this->authCodeRepositoryStub,
                $this->accessTokenRepositoryStub,
                $this->refreshTokenRepositoryStub,
                $this->authCodeTtl,
                $this->requestRulesManagerStub,
            )
        );
    }
}
