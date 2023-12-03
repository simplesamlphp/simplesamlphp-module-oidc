<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ClientIdRule;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\ClientIdRule
 */
class ClientIdRuleTest extends TestCase
{
    protected Stub $clientRepositoryStub;
    protected Stub $requestStub;
    protected Stub $resultBagStub;
    protected Stub $loggerServiceStub;

    /**
     * @throws Exception
     */
    protected function setUp(): void
    {
        $this->clientRepositoryStub = $this->createStub(ClientRepositoryInterface::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    public function testConstruct(): void
    {
        $this->assertInstanceOf(ClientIdRule::class, new ClientIdRule($this->clientRepositoryStub));
    }

    public function testCheckRuleEmptyClientIdThrows(): void
    {
        $this->requestStub->method('getQueryParams')->willReturn([]);
        $this->expectException(OidcServerException::class);
        (new ClientIdRule($this->clientRepositoryStub))->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        );
    }

    public function testCheckRuleInvalidClientThrows(): void
    {
        $this->requestStub->method('getQueryParams')->willReturn(['client_id' => '123']);
        $this->clientRepositoryStub->method('getClientEntity')->willReturn('invalid');
        $this->expectException(OidcServerException::class);
        (new ClientIdRule($this->clientRepositoryStub))->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        );
    }

    /**
     * @throws OidcServerException
     * @throws Exception
     */
    public function testCheckRuleForValidClientId(): void
    {
        $this->requestStub->method('getQueryParams')->willReturn(['client_id' => '123']);
        $client = $this->createStub(ClientEntityInterface::class);
        $this->clientRepositoryStub->method('getClientEntity')->willReturn($client);

        $result = (new ClientIdRule($this->clientRepositoryStub))->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        );
        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertInstanceOf(ClientEntityInterface::class, $result->getValue());
    }
}
