<?php

namespace SimpleSAML\Test\Module\oidc\Server\Grants;

use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AuthCodeRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;

/**
 * @covers \SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant
 */
class AuthCodeGrantTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\Stub|AuthCodeRepositoryInterface
     */
    protected $authCodeRepositoryStub;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub|AccessTokenRepositoryInterface
     */
    protected $accessTokenRepositoryStub;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub|RefreshTokenRepositoryInterface
     */
    protected $refreshTokenRepositoryStub;
    protected \DateInterval $authCodeTtl;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub|RequestRulesManager
     */
    protected $requestRulesManagerStub;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub|ConfigurationService
     */
    protected $configurationServiceStub;

    protected function setUp(): void
    {
        $this->authCodeRepositoryStub = $this->createStub(AuthCodeRepositoryInterface::class);
        $this->accessTokenRepositoryStub = $this->createStub(AccessTokenRepositoryInterface::class);
        $this->refreshTokenRepositoryStub = $this->createStub(RefreshTokenRepositoryInterface::class);
        $this->authCodeTtl = new \DateInterval('PT1M');
        $this->requestRulesManagerStub = $this->createStub(RequestRulesManager::class);
        $this->configurationServiceStub = $this->createStub(ConfigurationService::class);
    }

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
                $this->configurationServiceStub
            )
        );
    }
}
