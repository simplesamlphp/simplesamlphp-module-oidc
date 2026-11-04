<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories\Grant;

use DateInterval;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Grant\ImplicitGrantFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

#[CoversClass(ImplicitGrantFactory::class)]
class ImplicitGrantFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $requestRulesManagerMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getAccessTokenDuration')->willReturn(new DateInterval('PT1H'));
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
    }


    protected function buildAndValidateForConfidentialClient(): void
    {
        $clientEntityMock = $this->createMock(ClientEntity::class);
        $clientEntityMock->method('isConfidential')->willReturn(true);

        $resultBag = new ResultBag();
        $resultBag->add(new Result(RedirectUriRule::class, 'https://example.com/callback'));
        $resultBag->add(new Result(StateRule::class, 'test-state'));
        $resultBag->add(new Result(ClientIdRule::class, $clientEntityMock));

        $implicitGrant = (new ImplicitGrantFactory(
            $this->moduleConfigMock,
            $this->createMock(IdTokenBuilder::class),
            $this->requestRulesManagerMock,
            $this->createMock(AccessTokenRepository::class),
            $this->createMock(RequestParamsResolver::class),
            $this->createMock(AccessTokenEntityFactory::class),
        ))->build();

        $implicitGrant->validateAuthorizationRequestWithRequestRules(
            $this->createMock(ServerRequestInterface::class),
            $resultBag,
        );
    }


    public function testBuiltGrantRefusesConfidentialClientWhenOptionIsOn(): void
    {
        $this->moduleConfigMock->method('getDisallowImplicitForConfidentialClients')->willReturn(true);
        $this->requestRulesManagerMock->expects($this->never())->method('check');

        $this->expectException(OidcServerException::class);

        $this->buildAndValidateForConfidentialClient();
    }


    public function testBuiltGrantLetsConfidentialClientThroughWhenOptionIsOff(): void
    {
        $this->moduleConfigMock->method('getDisallowImplicitForConfidentialClients')->willReturn(false);
        // The rule check is where the request goes next; failing there stops the test before the rest of the flow.
        $this->requestRulesManagerMock->expects($this->once())->method('check')
            ->willThrowException(new RuntimeException('rules executed'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('rules executed');

        $this->buildAndValidateForConfidentialClient();
    }
}
