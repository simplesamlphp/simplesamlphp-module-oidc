<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\Grants;

use DateInterval;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AuthCodeRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

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
    protected Stub $requestParamsResolverStub;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->authCodeRepositoryStub = $this->createStub(AuthCodeRepositoryInterface::class);
        $this->accessTokenRepositoryStub = $this->createStub(AccessTokenRepositoryInterface::class);
        $this->refreshTokenRepositoryStub = $this->createStub(RefreshTokenRepositoryInterface::class);
        $this->authCodeTtl = new DateInterval('PT1M');
        $this->requestRulesManagerStub = $this->createStub(RequestRulesManager::class);
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
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
                $this->requestParamsResolverStub,
            ),
        );
    }
}
