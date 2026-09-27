<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use Exception;
use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Core\Factories\IdTokenHintFactory;
use SimpleSAML\OpenID\Core\IdTokenHint;
use SimpleSAML\OpenID\Jwks;
use Throwable;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule
 */
#[AllowMockObjectsWithoutExpectations]
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

    protected Stub $responseModeStub;


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
        $this->idTokenFactoryMock = $this->createMock(IdTokenHintFactory::class);
        $this->idTokenMock = $this->createMock(IdTokenHint::class);
        $this->coreMock->method('idTokenHintFactory')->willReturn($this->idTokenFactoryMock);
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
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
            [],
            $this->responseModeStub,
        ) ?? new Result(IdTokenHintRule::class);

        $this->assertNull($result->getValue());
    }


    /**
     * A hint that can not be parsed/validated (malformed JWS, missing/invalid required claims, or an expired
     * token) must be translated into a protocol-level invalid_request error, not surface as a raw exception.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleThrowsInvalidRequestForUnparsableIdToken(): void
    {
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('malformed');
        $this->idTokenFactoryMock->method('fromToken')
            ->with('malformed')
            ->willThrowException(new Exception('parse-failure'));

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
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
            ->willThrowException(new Exception('invalid-signature'));
        $this->idTokenFactoryMock->method('fromToken')
            ->with('invalid-it-token')
            ->willReturn($this->idTokenMock);
        $this->expectException(Throwable::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
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
        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
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
        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        ) ??
        new Result(IdTokenHintRule::class);

        $this->assertInstanceOf(IdTokenHint::class, $result->getValue());
    }


    /**
     * In the authorization flow (ClientRule present), a hint whose audience does not include the requesting client
     * is rejected, binding the hint to the requesting client.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleThrowsWhenClientNotInAudience(): void
    {
        $clientStub = $this->createStub(ClientEntityInterface::class);
        $clientStub->method('getIdentifier')->willReturn('client-b');

        $resultBagStub = $this->createStub(ResultBagInterface::class);
        $resultBagStub->method('get')->willReturnCallback(
            fn(string $key): ?Result => $key === ClientRule::class ?
                new Result(ClientRule::class, $clientStub) :
                null,
        );

        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('id-token');
        $this->idTokenMock->method('getIssuer')->willReturn(self::$issuer);
        $this->idTokenMock->method('getAudience')->willReturn(['client-a']);
        $this->idTokenFactoryMock->method('fromToken')->willReturn($this->idTokenMock);

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }


    /**
     * @return array<string,array{0:?string}>
     */
    public static function emptyIdTokenHintFlowProvider(): array
    {
        return [
            // The authorization endpoint has a validated redirect URI, so the refusal is redirected there.
            'the authorization flow, where a redirect URI has been validated' => ['https://rp.example.org/cb'],
            // The end session endpoint runs no ClientRedirectUriRule, so the refusal is answered directly.
            'the logout flow, where there is none' => [null],
        ];
    }


    /**
     * `id_token_hint=` is a hint the client announces and then does not send. It identifies no session, and
     * accepting it as an absent hint would let a request the client got wrong pass as a request which asked
     * for nothing. The refusal is made before the hint is parsed or any key is read.
     *
     * @throws \Throwable
     */
    #[DataProvider('emptyIdTokenHintFlowProvider')]
    public function testRefusesAnEmptyIdTokenHint(?string $redirectUri): void
    {
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('');

        $resultBagStub = $this->createStub(ResultBagInterface::class);
        $resultBagStub->method('getOrFail')->willReturnCallback(
            fn(string $key): Result => $key === StateRule::class ?
                new Result(StateRule::class, 'state123') :
                self::fail('The rule asked the bag for ' . $key . ', which this test does not model.'),
        );
        $resultBagStub->method('get')->willReturnCallback(
            fn(string $key): ?Result => $key === ClientRedirectUriRule::class && $redirectUri !== null ?
                new Result(ClientRedirectUriRule::class, $redirectUri) :
                null,
        );

        $loggerServiceMock = $this->createMock(LoggerService::class);
        $loggerServiceMock->expects($this->once())
            ->method('notice')
            ->with('Request rejected: `id_token_hint` was provided but empty.');
        // Neither the hint nor this OP's keys are read: the refusal comes first.
        $this->coreMock->expects($this->never())->method('idTokenHintFactory');
        $this->jwksMock->expects($this->never())->method('jwksDecoratorFactory');

        try {
            $this->sut()->checkRule(
                $this->requestStub,
                $resultBagStub,
                $loggerServiceMock,
                [],
                $this->responseModeStub,
            );
            $this->fail('An empty id_token_hint must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertSame('Received empty id_token_hint', $exception->getHint());
            $this->assertSame($redirectUri, $exception->getRedirectUri());
            $this->assertSame('state123', $exception->getPayload()['state']);
        }
    }
}
