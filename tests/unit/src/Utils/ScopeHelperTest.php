<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\ScopeHelper;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\ScopeHelper
 */
class ScopeHelperTest extends TestCase
{
    protected Stub $scopeEntityOpenIdStub;
    protected Stub $scopeEntityProfileStub;
    protected array $scopeEntitiesArray;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->scopeEntityOpenIdStub = $this->createStub(ScopeEntityInterface::class);
        $this->scopeEntityOpenIdStub->method('getIdentifier')->willReturn('openid');
        $this->scopeEntityProfileStub = $this->createStub(ScopeEntityInterface::class);
        $this->scopeEntityProfileStub->method('getIdentifier')->willReturn('profile');
        $this->scopeEntitiesArray = [
            $this->scopeEntityOpenIdStub,
            $this->scopeEntityProfileStub,
        ];
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
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
