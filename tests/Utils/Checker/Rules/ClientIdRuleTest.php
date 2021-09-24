<?php

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
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
    protected $clientRepository;
    protected $rule;
    protected $requestStub;
    protected $resultBagStub;
    protected $loggerServiceStub;

    protected function setUp(): void
    {
        $this->clientRepository = $this->createStub(ClientRepositoryInterface::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    public function testConstruct(): void
    {
        $this->assertInstanceOf(ClientIdRule::class, new ClientIdRule($this->clientRepository));
    }

    public function testCheckRuleEmptyClientIdThrows(): void
    {
        $this->requestStub->method('getQueryParams')->willReturn([]);
        $this->expectException(OidcServerException::class);
        (new ClientIdRule($this->clientRepository))->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            []
        );
    }

    public function testCheckRuleInvalidClientThrows(): void
    {
        $this->requestStub->method('getQueryParams')->willReturn(['client_id' => '123']);
        $this->clientRepository->method('getClientEntity')->willReturn('invalid');
        $this->expectException(OidcServerException::class);
        (new ClientIdRule($this->clientRepository))->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            []
        );
    }

    public function testCheckRuleForValidClientId(): void
    {
        $this->requestStub->method('getQueryParams')->willReturn(['client_id' => '123']);
        $client = $this->createStub(ClientEntityInterface::class);
        $this->clientRepository->method('getClientEntity')->willReturn($client);

        $result = (new ClientIdRule($this->clientRepository))->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            []
        );
        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertInstanceOf(ClientEntityInterface::class, $result->getValue());
    }
}
