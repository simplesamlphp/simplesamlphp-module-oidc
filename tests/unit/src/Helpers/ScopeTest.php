<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Helpers;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Helpers\Scope;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

#[CoversClass(Scope::class)]
class ScopeTest extends TestCase
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

    protected function sut(): Scope
    {
        return new Scope();
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCanCheckScopeExistence(): void
    {
        $this->assertTrue($this->sut()->exists($this->scopeEntitiesArray, 'openid'));
        $this->assertTrue($this->sut()->exists($this->scopeEntitiesArray, 'profile'));
        $this->assertFalse($this->sut()->exists($this->scopeEntitiesArray, 'invalid'));
    }

    public function testThrowsForInvalidScopeEntity(): void
    {
        $this->expectException(OidcServerException::class);

        $this->sut()->exists(['invalid'], 'test');
    }
}
