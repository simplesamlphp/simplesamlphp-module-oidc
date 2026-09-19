<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\ResourceServer;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;

/**
 * The module's stand-in for League's resource server: one method, which hands the request to the bearer
 * token validator and answers with the request the validator hands back, attributes and all. The userinfo
 * and credential endpoints authenticate their requests through it.
 */
#[CoversClass(ResourceServer::class)]
#[AllowMockObjectsWithoutExpectations]
class ResourceServerTest extends TestCase
{
    protected MockObject $bearerTokenValidatorMock;

    protected MockObject $requestMock;


    protected function setUp(): void
    {
        $this->bearerTokenValidatorMock = $this->createMock(BearerTokenValidator::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
    }


    protected function sut(): ResourceServer
    {
        return new ResourceServer($this->bearerTokenValidatorMock);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(ResourceServer::class, $this->sut());
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testAnswersWithTheRequestTheValidatorHandsBack(): void
    {
        $validatedRequest = $this->createMock(ServerRequestInterface::class);
        $this->bearerTokenValidatorMock->expects($this->once())
            ->method('validateAuthorization')
            ->with($this->identicalTo($this->requestMock))
            ->willReturn($validatedRequest);

        $this->assertSame($validatedRequest, $this->sut()->validateAuthenticatedRequest($this->requestMock));
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testLetsTheValidatorsRefusalThrough(): void
    {
        $refusal = OidcServerException::accessDenied('Access token not found.');
        $this->bearerTokenValidatorMock->method('validateAuthorization')->willThrowException($refusal);

        $this->expectExceptionObject($refusal);

        $this->sut()->validateAuthenticatedRequest($this->requestMock);
    }
}
