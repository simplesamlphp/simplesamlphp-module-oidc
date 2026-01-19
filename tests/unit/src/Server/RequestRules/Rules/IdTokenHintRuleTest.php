<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Core\Factories\IdTokenFactory;
use SimpleSAML\OpenID\Core\IdToken;
use SimpleSAML\OpenID\Jwks;
use Throwable;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule
 */
class IdTokenHintRuleTest extends TestCase
{
    protected Stub $requestStub;
    protected Stub $resultBagStub;
    protected Stub $moduleConfigStub;

    protected static string $certFolder;
    protected static string $privateKeyPath;
    protected static string $publicKeyPath;
    protected static CryptKey $privateKey;
    protected static CryptKey $publicKey;

    protected static string $issuer = 'https://example.org';

    protected Stub $loggerServiceStub;
    protected Stub $requestParamsResolverStub;
    protected Helpers $helpers;
    protected MockObject $jwksMock;
    protected MockObject $coreMock;
    protected MockObject $idTokenFactoryMock;
    protected MockObject $idTokenMock;

    /**
     * @throws \ReflectionException
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);

        $this->resultBagStub = $this->createStub(ResultBagInterface::class);

        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->moduleConfigStub->method('getIssuer')->willReturn(self::$issuer);

        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);

        $this->helpers = new Helpers();

        $this->jwksMock = $this->createMock(Jwks::class);
        $this->coreMock = $this->createMock(Core::class);
        $this->idTokenFactoryMock = $this->createMock(IdTokenFactory::class);
        $this->idTokenMock = $this->createMock(IdToken::class);
        $this->coreMock->method('idTokenFactory')->willReturn($this->idTokenFactoryMock);
    }

    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
        ?ModuleConfig $moduleConfig = null,
        ?Jwks $jwks = null,
        ?Core $core = null,
    ): IdTokenHintRule {

        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;
        $moduleConfig ??= $this->moduleConfigStub;
        $jwks ??= $this->jwksMock;
        $core ??= $this->coreMock;

        return new IdTokenHintRule(
            $requestParamsResolver,
            $helpers,
            $moduleConfig,
            $jwks,
            $core,
        );
    }

    public function testConstruct(): void
    {
        $this->assertInstanceOf(IdTokenHintRule::class, $this->sut());
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleIsNullWhenParamNotSet(): void
    {
        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        ) ?? new Result(IdTokenHintRule::class);

        $this->assertNull($result->getValue());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleThrowsForMalformedIdToken(): void
    {
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('malformed');
        $this->expectException(Throwable::class);
        $this->sut()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleThrowsForIdTokenWithInvalidSignature(): void
    {
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')
            ->willReturn('invalid-it-token');
        $this->idTokenMock->method('getIssuer')->willReturn(self::$issuer);
        $this->idTokenMock->method('verifyWithKeySet')
            ->willThrowException(new \Exception('invalid-signature'));
        $this->idTokenFactoryMock->method('fromToken')
            ->with('invalid-it-token')
            ->willReturn($this->idTokenMock);
        $this->expectException(Throwable::class);
        $this->sut()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);
    }

    /**
     * @throws \ReflectionException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleThrowsForIdTokenWithInvalidIssuer(): void
    {
        $this->requestStub->method('getMethod')->willReturn('GET');
        $this->idTokenMock->method('getIssuer')->willReturn('invalid');
        $this->idTokenFactoryMock->method('fromToken')
            ->with('id-token')
            ->willReturn($this->idTokenMock);

        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')
            ->willReturn('id-token');
        $this->expectException(Throwable::class);
        $this->sut()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);
    }

    /**
     * @throws \ReflectionException
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRulePassesForValidIdToken(): void
    {
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')
            ->willReturn('id-token');
        $this->idTokenMock->method('getIssuer')->willReturn(self::$issuer);
        $this->idTokenFactoryMock->method('fromToken')
            ->willReturn($this->idTokenMock);
        $result = $this->sut()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub) ??
        new Result(IdTokenHintRule::class);

        $this->assertInstanceOf(IdToken::class, $result->getValue());
    }
}
