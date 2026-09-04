<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\Controllers\JwksController;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPoolBag;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jwks\Factories\JwksDecoratorFactory;
use SimpleSAML\OpenID\Jwks\JwksDecorator;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\JwksController
 */
#[AllowMockObjectsWithoutExpectations]
class JwksControllerTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $jwks;

    protected MockObject $routesMock;

    protected MockObject $jwksDecoratorFactoryMock;

    protected MockObject $jwksDecoratorMock;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->jwks = $this->createMock(Jwks::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            fn (
                array|null $data = null,
                int $status = 200,
                array $headers = [],
                bool $json = false,
            ) => new JsonResponse($data, $status, $headers, $json),
        );

        $this->jwksDecoratorMock = $this->createMock(JwksDecorator::class);
        $this->jwksDecoratorFactoryMock = $this->createMock(JwksDecoratorFactory::class);
        $this->jwksDecoratorFactoryMock->method('fromJwkDecorators')->willReturn($this->jwksDecoratorMock);

        $this->jwks->method('jwksDecoratorFactory')->willReturn($this->jwksDecoratorFactoryMock);
    }


    protected function mock(
        ?ModuleConfig $moduleConfig = null,
        ?Jwks $jwks = null,
        ?Routes $routes = null,
    ): JwksController {
        $moduleConfig ??= $this->moduleConfigMock;
        $jwks ??= $this->jwks;
        $routes ??= $this->routesMock;

        return new JwksController(
            $moduleConfig,
            $jwks,
            $routes,
        );
    }


    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            JwksController::class,
            $this->mock(),
        );
    }


    public function testItReturnsJsonKeys(): void
    {
        $keys = [
            'keys' => [
                'kty' => 'RSA',
                'n' => 'n',
                'e' => 'e',
                'use' => 'sig',
                'kid' => 'oidc',
                'alg' => 'RS256',
            ],
        ];

        $this->jwksDecoratorMock->expects($this->once())->method('jsonSerialize')->willReturn($keys);

        $this->assertSame(
            $keys,
            json_decode((string) $this->mock()->__invoke()->getContent(), true),
        );
    }


    public function testItAlwaysReturnsAccessControlAllowOrigin(): void
    {
        $response = $this->mock()->jwks();
        $this->assertTrue($response->headers->has('Access-Control-Allow-Origin'));
        $this->assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
    }


    /**
     * Under the `https` issuer identity a credential names its signing key by its identifier in this
     * key set and carries the key nowhere else, so withdrawing it when issuance is switched off would
     * make every credential already issued unverifiable.
     */
    public function testItKeepsPublishingVciKeysForCredentialsWhichNameThemHere(): void
    {
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(false);
        $this->moduleConfigMock->method('getVciStatusListPoolBag')
            ->willReturn(new StatusListPoolBag());
        $this->moduleConfigMock->method('getVciIssuerIdentifierMode')
            ->willReturn(VciIssuerIdentifierModeEnum::Https);
        $this->moduleConfigMock->expects($this->once())->method('getVciSignatureKeyPairBag')
            ->willReturn(new SignatureKeyPairBag());

        $this->mock()->__invoke();
    }


    /**
     * The identity modes which carry their key with the credential do not need it here, so the key set
     * stays as it was before the issuer identity became configurable.
     */
    public function testItWithdrawsVciKeysForIdentitiesWhichDoNotNeedThem(): void
    {
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(false);
        $this->moduleConfigMock->method('getVciStatusListPoolBag')
            ->willReturn(new StatusListPoolBag());
        $this->moduleConfigMock->method('getVciIssuerIdentifierMode')
            ->willReturn(VciIssuerIdentifierModeEnum::DidJwk);
        $this->moduleConfigMock->expects($this->never())->method('getVciSignatureKeyPairBag');

        $this->mock()->__invoke();
    }


    /**
     * A pool on the `jwks` profile has its tokens verified through this key set, so the key stays
     * published even while issuance is off.
     */
    public function testItKeepsPublishingVciKeysForAPoolWhoseTokensNameThemHere(): void
    {
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(false);
        $this->moduleConfigMock->method('getVciIssuerIdentifierMode')
            ->willReturn(VciIssuerIdentifierModeEnum::DidJwk);
        $this->moduleConfigMock->method('isAnyStatusListPoolOnKeyProfile')
            ->with(StatusListKeyProfileEnum::Jwks)
            ->willReturn(true);
        $this->moduleConfigMock->expects($this->once())->method('getVciSignatureKeyPairBag')
            ->willReturn(new SignatureKeyPairBag());

        $this->mock()->__invoke();
    }


    /**
     * Whether one pool needs its key published must not depend on every other pool being valid.
     * Building the bag is all or nothing, so a deployment mixing a `jwks` pool with a `did_web` one
     * whose issuer identifier is missing or malformed would otherwise have this answer "no" -- and the
     * key that the `jwks` pool's already published tokens are verified through withdrawn, over an
     * option those tokens never used.
     */
    public function testAPoolBrokenOnAnotherProfileDoesNotWithdrawTheKeyAValidPoolNeeds(): void
    {
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(false);
        $this->moduleConfigMock->method('getVciIssuerIdentifierMode')
            ->willReturn(VciIssuerIdentifierModeEnum::DidJwk);
        $this->moduleConfigMock->method('isAnyStatusListPoolOnKeyProfile')->willReturn(true);

        // The question is answered without ever building them, so one which cannot be built is not
        // able to change the answer.
        $this->moduleConfigMock->expects($this->never())->method('getVciStatusListPoolBag');
        $this->moduleConfigMock->expects($this->once())->method('getVciSignatureKeyPairBag')
            ->willReturn(new SignatureKeyPairBag());

        $this->mock()->__invoke();
    }


    /**
     * A key set which cannot be served takes down verification of every token this issuer has ever
     * signed, so a malformed issuer identity must not reach it.
     */
    public function testAMalformedIssuerIdentityModeDoesNotTakeTheKeySetDown(): void
    {
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(false);
        $this->moduleConfigMock->method('getVciStatusListPoolBag')
            ->willReturn(new StatusListPoolBag());
        $this->moduleConfigMock->method('getVciIssuerIdentifierMode')
            ->willThrowException(new ConfigurationError('nope'));
        $this->moduleConfigMock->expects($this->never())->method('getVciSignatureKeyPairBag');

        $response = $this->mock()->jwks();

        $this->assertSame(200, $response->getStatusCode());
    }
}
