<?php

namespace SimpleSAML\Test\Module\oidc\Utils;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\ScopeHelper;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\ScopeHelper
 */
class ScopeHelperTest extends TestCase
{
    /**
     * @var ScopeEntityInterface|ScopeEntityInterface
     */
    protected $scopeEntityOpenId;
    /**
     * @var ScopeEntityInterface|ScopeEntityInterface
     */
    protected $scopeEntityProfile;
    protected array $scopeEntitiesArray;

    protected function setUp(): void
    {
        $this->scopeEntityOpenId = $this->createStub(ScopeEntityInterface::class);
        $this->scopeEntityOpenId->method('getIdentifier')->willReturn('openid');
        $this->scopeEntityProfile = $this->createStub(ScopeEntityInterface::class);
        $this->scopeEntityProfile->method('getIdentifier')->willReturn('profile');
        $this->scopeEntitiesArray = [
            $this->scopeEntityOpenId,
            $this->scopeEntityProfile
        ];
    }

    public function testCanCheckScopeExistence(): void
    {
        $this->assertTrue(ScopeHelper::scopeExists($this->scopeEntitiesArray, 'openid'));
        $this->assertTrue(ScopeHelper::scopeExists($this->scopeEntitiesArray, 'profile'));
        $this->assertFalse(ScopeHelper::scopeExists($this->scopeEntitiesArray, 'invalid'));
    }

    public function testThrowsForInvalidScopeEntity(): void
    {
        $this->expectException(OidcServerException::class);

        ScopeHelper::scopeExists(['invalid'], 'test');
    }
}
