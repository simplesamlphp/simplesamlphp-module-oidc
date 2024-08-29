<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\RequestRules\Rules;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientIdRule
 */
class ClientIdRuleTest extends TestCase
{
    protected Stub $clientEntityStub;
    protected Stub $clientRepositoryStub;
    protected Stub $requestStub;
    protected Stub $resultBagStub;
    protected Stub $loggerServiceStub;
    protected Stub $requestParamsResolverStub;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->clientEntityStub = $this->createStub(ClientEntityInterface::class);
        $this->clientRepositoryStub = $this->createStub(ClientRepositoryInterface::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
    }

    protected function mock(): ClientIdRule
    {
        return new ClientIdRule(
            $this->requestParamsResolverStub,
            $this->clientRepositoryStub,
        );
    }

    public function testConstruct(): void
    {
        $this->assertInstanceOf(ClientIdRule::class, $this->mock());
    }

    public function testCheckRuleEmptyClientIdThrows(): void
    {
        $this->requestParamsResolverStub->method('getBasedOnAllowedMethods')->willReturn(null);
        $this->expectException(OidcServerException::class);
        $this->mock()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        );
    }

    public function testCheckRuleInvalidClientThrows(): void
    {
        $this->requestParamsResolverStub->method('getBasedOnAllowedMethods')->willReturn('123');
        $this->clientRepositoryStub->method('getClientEntity')->willReturn('invalid');
        $this->expectException(OidcServerException::class);
        $this->mock()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testCheckRuleForValidClientId(): void
    {
        $this->requestParamsResolverStub->method('getBasedOnAllowedMethods')->willReturn('123');
        $this->clientRepositoryStub->method('getClientEntity')->willReturn($this->clientEntityStub);

        $result = $this->mock()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        );
        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertInstanceOf(ClientEntityInterface::class, $result->getValue());
    }
}
