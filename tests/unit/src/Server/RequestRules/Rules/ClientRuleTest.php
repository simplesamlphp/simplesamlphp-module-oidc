<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\Module\oidc\Utils\FederationParticipationValidator;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Federation;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule
 */
class ClientRuleTest extends TestCase
{
    protected Stub $clientEntityStub;
    protected Stub $clientRepositoryStub;
    protected Stub $requestStub;
    protected Stub $resultBagStub;
    protected Stub $loggerServiceStub;
    protected Stub $requestParamsResolverStub;
    protected Stub $moduleConfigStub;
    protected Stub $federationStub;
    protected Stub $federationCacheStub;
    protected Stub $clientEntityFactoryStub;
    protected Stub $helpersStub;
    protected Stub $jwksResolverStub;
    protected Stub $federationParticipationValidatorStub;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->clientEntityStub = $this->createStub(ClientEntityInterface::class);
        $this->clientRepositoryStub = $this->createStub(ClientRepository::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->federationStub = $this->createStub(Federation::class);
        $this->federationCacheStub = $this->createStub(FederationCache::class);
        $this->clientEntityFactoryStub = $this->createStub(ClientEntityFactory::class);
        $this->helpersStub = $this->createStub(Helpers::class);
        $this->jwksResolverStub = $this->createStub(JwksResolver::class);
        $this->federationParticipationValidatorStub = $this->createStub(FederationParticipationValidator::class);
    }

    protected function sut(): ClientRule
    {
        return new ClientRule(
            $this->requestParamsResolverStub,
            $this->helpersStub,
            $this->clientRepositoryStub,
            $this->moduleConfigStub,
            $this->clientEntityFactoryStub,
            $this->federationStub,
            $this->jwksResolverStub,
            $this->federationParticipationValidatorStub,
            $this->loggerServiceStub,
            $this->federationCacheStub,
        );
    }

    public function testConstruct(): void
    {
        $this->assertInstanceOf(ClientRule::class, $this->sut());
    }

    public function testCheckRuleEmptyClientIdThrows(): void
    {
        $this->requestParamsResolverStub->method('getBasedOnAllowedMethods')->willReturn(null);
        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule(
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
        $this->sut()->checkRule(
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
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('123');
        $this->clientRepositoryStub->method('getClientEntity')->willReturn($this->clientEntityStub);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        );
        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertInstanceOf(ClientEntityInterface::class, $result->getValue());
    }
}
