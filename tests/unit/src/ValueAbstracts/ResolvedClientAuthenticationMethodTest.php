<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\ValueAbstracts;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;

#[CoversClass(ResolvedClientAuthenticationMethod::class)]
class ResolvedClientAuthenticationMethodTest extends TestCase
{
    protected MockObject $clientMock;

    protected function setUp(): void
    {
        $this->clientMock = $this->createMock(ClientEntityInterface::class);
    }

    protected function sut(
        ?ClientEntityInterface $client = null,
        ?ClientAuthenticationMethodsEnum $clientAuthenticationMethod = null,
    ): ResolvedClientAuthenticationMethod {
        $client ??= $this->clientMock;
        $clientAuthenticationMethod ??= ClientAuthenticationMethodsEnum::ClientSecretBasic;

        return new ResolvedClientAuthenticationMethod(
            $client,
            $clientAuthenticationMethod,
        );
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(ResolvedClientAuthenticationMethod::class, $this->sut());
    }

    public function testCanGetProperties(): void
    {
        $sut = $this->sut(
            $this->clientMock,
            ClientAuthenticationMethodsEnum::ClientSecretPost,
        );

        $this->assertSame($this->clientMock, $sut->getClient());
        $this->assertSame(ClientAuthenticationMethodsEnum::ClientSecretPost, $sut->getClientAuthenticationMethod());
    }
}
