<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Entities;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\JwtTypesEnum;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Helpers;
use SimpleSAML\OpenID\Helpers\DateTime;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\OAuth2;
use SimpleSAML\OpenID\OAuth2\Factories\JwtAccessTokenFactory;
use SimpleSAML\OpenID\OAuth2\JwtAccessToken;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;

/**
 * @covers \SimpleSAML\Module\oidc\Entities\AccessTokenEntity
 */
#[AllowMockObjectsWithoutExpectations]
class AccessTokenEntityTest extends TestCase
{
    protected array $state;

    protected string $id = '123';

    protected array $scopes;

    protected string $expiresAt;

    protected string $userId = 'user123';

    protected bool $isRevoked = false;

    protected string $authCodeId = 'authCode123';

    protected array $requestedClaims = ['key' => 'value'];

    protected string $clientId = 'client123';

    protected ClientEntity $clientEntityStub;

    protected ScopeEntity $scopeEntityOpenId;

    protected ScopeEntity $scopeEntityProfile;

    protected MockObject $unencryptedTokenMock;

    protected DateTimeImmutable $expiryDateTime;

    protected MockObject $moduleConfigMock;

    protected MockObject $oAuth2Mock;

    protected MockObject $signatureKeyPairMock;

    protected MockObject $signatureKeyPairBagMock;

    protected MockObject $jwtAccessTokenFactoryMock;

    protected int $currentTimestamp = 1700000000;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->clientEntityStub = $this->createStub(ClientEntity::class);
        $this->clientEntityStub->method('getIdentifier')->willReturn($this->clientId);

        $this->scopeEntityOpenId = $this->createStub(ScopeEntity::class);
        $this->scopeEntityOpenId->method('getIdentifier')->willReturn('openid');
        $this->scopeEntityOpenId->method('jsonSerialize')->willReturn('openid');
        $this->scopeEntityProfile = $this->createStub(ScopeEntity::class);
        $this->scopeEntityProfile->method('getIdentifier')->willReturn('profile');
        $this->scopeEntityProfile->method('jsonSerialize')->willReturn('profile');

        $this->scopes = [
            $this->scopeEntityOpenId->getIdentifier() => $this->scopeEntityOpenId,
            $this->scopeEntityProfile->getIdentifier() => $this->scopeEntityProfile,
        ];

        $this->expiryDateTime = (new DateTimeImmutable('now', new DateTimeZone('UTC')))
            ->add(new DateInterval('PT1M'));

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://op.example.org');
        $this->oAuth2Mock = $this->createMock(OAuth2::class);

        $dateTimeHelperMock = $this->createMock(DateTime::class);
        $dateTimeHelperMock->method('getUtc')
            ->willReturn((new DateTimeImmutable('@' . $this->currentTimestamp)));
        $helpersMock = $this->createMock(Helpers::class);
        $helpersMock->method('dateTime')->willReturn($dateTimeHelperMock);
        $this->oAuth2Mock->method('helpers')->willReturn($helpersMock);

        $this->jwtAccessTokenFactoryMock = $this->createMock(JwtAccessTokenFactory::class);
        $this->oAuth2Mock->method('jwtAccessTokenFactory')->willReturn($this->jwtAccessTokenFactoryMock);

        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getKeyId')->willReturn('kid123');
        $keyPairMock->method('getPrivateKey')->willReturn($this->createMock(JwkDecorator::class));
        $this->signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $this->signatureKeyPairMock->method('getSignatureAlgorithm')
            ->willReturn(SignatureAlgorithmEnum::RS256);
        $this->signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        $this->signatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);
        $this->signatureKeyPairBagMock->method('getFirstOrFail')
            ->willReturn($this->signatureKeyPairMock);

        $this->moduleConfigMock->method('getProtocolSignatureKeyPairBag')
            ->willReturn($this->signatureKeyPairBagMock);
    }


    public function mock(
        ?array $scopes = null,
        ?ClientEntity $clientEntity = null,
        ?string $subject = null,
        array $userClaims = [],
    ): AccessTokenEntity {
        return new AccessTokenEntity(
            $this->id,
            $clientEntity ?? $this->clientEntityStub,
            $scopes ?? $this->scopes,
            $this->expiryDateTime,
            $this->oAuth2Mock,
            $this->moduleConfigMock,
            $this->userId,
            $this->authCodeId,
            $this->requestedClaims,
            $this->isRevoked,
            subject: $subject,
            userClaims: $userClaims,
        );
    }


    /**
     * Capture the payload and header handed to the library's JWT access token factory when the token is
     * serialised.
     *
     * @return array{0: array, 1: array}
     */
    protected function serialise(AccessTokenEntity $accessTokenEntity): array
    {
        $captured = [];
        $this->jwtAccessTokenFactoryMock->expects($this->once())
            ->method('fromData')
            ->willReturnCallback(
                function (
                    JwkDecorator $signingKey,
                    SignatureAlgorithmEnum $signatureAlgorithm,
                    array $payload,
                    array $header,
                ) use (&$captured): JwtAccessToken {
                    $captured = [$payload, $header];
                    $jwtAccessTokenMock = $this->createMock(JwtAccessToken::class);
                    $jwtAccessTokenMock->method('getToken')->willReturn('token');
                    return $jwtAccessTokenMock;
                },
            );

        $accessTokenEntity->toString();

        return $captured;
    }


    /**
     * The library's OAuth2 tools with a real signing key, for the tests which mint a token and read it back:
     * the factory validates the payload against RFC 9068 and writes the "typ" header, and only a real
     * factory shows either.
     *
     * @return array{0: \SimpleSAML\OpenID\OAuth2, 1: \SimpleSAML\Module\oidc\ModuleConfig}
     */
    protected function realOAuth2AndModuleConfig(): array
    {
        $oAuth2 = new OAuth2(
            supportedAlgorithms: new SupportedAlgorithms(new SignatureAlgorithmBag(SignatureAlgorithmEnum::ES256)),
        );

        $jwk = JWKFactory::createECKey('P-256');
        $signatureKeyPair = new SignatureKeyPair(
            SignatureAlgorithmEnum::ES256,
            new KeyPair(new JwkDecorator($jwk), new JwkDecorator($jwk->toPublic()), 'kid123'),
        );
        $signatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);
        $signatureKeyPairBagMock->method('getFirstOrFail')->willReturn($signatureKeyPair);

        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getIssuer')->willReturn('https://op.example.org');
        $moduleConfigMock->method('getProtocolSignatureKeyPairBag')->willReturn($signatureKeyPairBagMock);

        return [$oAuth2, $moduleConfigMock];
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(
            AccessTokenEntity::class,
            $this->mock(),
        );
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testHasProperState(): void
    {
        $accessTokenEntityState = $this->mock()->getState();

        $this->assertSame($this->id, $accessTokenEntityState['id']);
        $this->assertSame(json_encode($this->scopes, JSON_THROW_ON_ERROR), $accessTokenEntityState['scopes']);

        $this->assertSame($this->requestedClaims, $this->mock()->getRequestedClaims());
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testHasImmutableStringRepresentation(): void
    {
        $instance = $this->mock();

        $stringRepresentation = $instance->toString();

        $this->assertIsString($instance->toString());

        $this->assertSame($stringRepresentation, (string) $instance);
        $this->assertSame($stringRepresentation, $instance->toString());
    }


    public function testJwtCarriesRfc9068Envelope(): void
    {
        [$payload, $header] = $this->serialise($this->mock());

        // The "typ" header is the factory's to write (see testMintsAJwtAccessTokenTheLibraryReadsBack).
        $this->assertSame([ClaimsEnum::Kid->value => 'kid123'], $header);

        $this->assertSame('https://op.example.org', $payload[ClaimsEnum::Iss->value]);
        $this->assertSame($this->id, $payload[ClaimsEnum::Jti->value]);
        $this->assertSame($this->clientId, $payload[ClaimsEnum::Aud->value]);
        $this->assertSame($this->clientId, $payload[ClaimsEnum::ClientId->value]);
        $this->assertSame($this->userId, $payload[ClaimsEnum::Sub->value]);
        $this->assertSame($this->currentTimestamp, $payload[ClaimsEnum::Iat->value]);
        $this->assertSame($this->currentTimestamp, $payload[ClaimsEnum::Nbf->value]);
        $this->assertSame($this->expiryDateTime->getTimestamp(), $payload[ClaimsEnum::Exp->value]);
        $this->assertSame('openid profile', $payload[ClaimsEnum::Scope->value]);
        // The pre-RFC 9068 array stays for consumers written against it.
        $this->assertSame(array_values($this->scopes), $payload['scopes']);
        $this->assertArrayNotHasKey(ClaimsEnum::IssuerState->value, $payload);
    }


    public function testJwtOmitsScopeClaimsWhenNoScopeWasGranted(): void
    {
        [$payload] = $this->serialise($this->mock([]));

        $this->assertArrayNotHasKey(ClaimsEnum::Scope->value, $payload);
        $this->assertArrayNotHasKey('scopes', $payload);
        $this->assertSame($this->clientId, $payload[ClaimsEnum::ClientId->value]);
    }


    public function testJwtKeepsFalsyButValidScopeAndClientIdentifiers(): void
    {
        $zeroScope = $this->createStub(ScopeEntity::class);
        $zeroScope->method('getIdentifier')->willReturn('0');
        $zeroScope->method('jsonSerialize')->willReturn('0');
        $zeroClient = $this->createStub(ClientEntity::class);
        $zeroClient->method('getIdentifier')->willReturn('0');

        [$payload] = $this->serialise($this->mock(['0' => $zeroScope], $zeroClient));

        $this->assertSame('0', $payload[ClaimsEnum::Scope->value]);
        $this->assertSame([$zeroScope], $payload['scopes']);
        $this->assertSame('0', $payload[ClaimsEnum::ClientId->value]);
        $this->assertSame('0', $payload[ClaimsEnum::Aud->value]);
    }


    public function testJwtCarriesIssuerStateWhenSet(): void
    {
        $accessTokenEntity = new AccessTokenEntity(
            $this->id,
            $this->clientEntityStub,
            $this->scopes,
            $this->expiryDateTime,
            $this->oAuth2Mock,
            $this->moduleConfigMock,
            $this->userId,
            issuerState: 'issuer-state-123',
        );

        [$payload] = $this->serialise($accessTokenEntity);

        $this->assertSame('issuer-state-123', $payload[ClaimsEnum::IssuerState->value]);
        $this->assertSame($this->userId, $payload[ClaimsEnum::Sub->value]);
    }


    /**
     * RFC 9068 section 2.2 has "sub" REQUIRED; for a token with no resource owner behind it (a pre-authorized code
     * issued without a user) it names the client: "the value of "sub" SHOULD correspond to an identifier the
     * authorization server uses to indicate the client application".
     */
    public function testJwtNamesTheClientAsSubjectWhenThereIsNoUser(): void
    {
        $accessTokenEntity = new AccessTokenEntity(
            $this->id,
            $this->clientEntityStub,
            $this->scopes,
            $this->expiryDateTime,
            $this->oAuth2Mock,
            $this->moduleConfigMock,
        );

        [$payload] = $this->serialise($accessTokenEntity);

        $this->assertSame($this->clientId, $payload[ClaimsEnum::Sub->value]);
        $this->assertArrayNotHasKey(ClaimsEnum::IssuerState->value, $payload);
        $this->assertSame($this->clientId, $payload[ClaimsEnum::ClientId->value]);
    }


    public function testCarriesTheSubjectAndUserClaimsItWasMintedWith(): void
    {
        $accessTokenEntity = $this->mock(subject: 'resolved-subject', userClaims: ['voperson_id' => 'v1']);

        $this->assertSame('resolved-subject', $accessTokenEntity->getSubject());
        $this->assertSame(['voperson_id' => 'v1'], $accessTokenEntity->getUserClaims());
        // Neither is persisted: the row has no column for them.
        $this->assertArrayNotHasKey('subject', $accessTokenEntity->getState());
        $this->assertArrayNotHasKey('user_claims', $accessTokenEntity->getState());
    }


    /**
     * The JWT "sub" is the subject resolved at minting, whatever the internal user identifier is.
     */
    public function testJwtCarriesTheMintedSubjectOverTheUserIdentifier(): void
    {
        [$payload] = $this->serialise($this->mock(subject: 'resolved-subject'));

        $this->assertSame('resolved-subject', $payload[ClaimsEnum::Sub->value]);
    }


    /**
     * An entity built without a subject (rehydrated from storage, which no production path serialises) falls
     * back to the internal identifier, the "sub" of every access token before the subject was resolved at minting.
     */
    public function testJwtFallsBackToTheUserIdentifierWithoutAMintedSubject(): void
    {
        [$payload] = $this->serialise($this->mock());

        $this->assertSame($this->userId, $payload[ClaimsEnum::Sub->value]);
    }


    public function testJwtKeepsAFalsyButValidSubject(): void
    {
        [$payload] = $this->serialise($this->mock(subject: '0'));

        $this->assertSame('0', $payload[ClaimsEnum::Sub->value]);
    }


    /**
     * The user claims are placed next to the envelope, keeping a valid falsy value (an assurance of "0", a
     * boolean false) which the envelope's own absent-value filter would have dropped.
     */
    public function testJwtCarriesTheUserClaimsNextToTheEnvelope(): void
    {
        [$payload] = $this->serialise($this->mock(
            subject: 'resolved-subject',
            userClaims: [
                'voperson_id' => 'v1@example.org',
                'eduperson_assurance' => ['0'],
                'flag' => false,
                'zero' => 0,
            ],
        ));

        $this->assertSame('v1@example.org', $payload['voperson_id']);
        $this->assertSame(['0'], $payload['eduperson_assurance']);
        $this->assertFalse($payload['flag']);
        $this->assertSame(0, $payload['zero']);
        $this->assertSame('resolved-subject', $payload[ClaimsEnum::Sub->value]);
        $this->assertSame($this->clientId, $payload[ClaimsEnum::ClientId->value]);
    }


    /**
     * The envelope is written over the user claims, so even a user claim which gets past the option validation
     * under a reserved name can not replace "iss", "sub", "aud", "client_id", "scope" or the legacy "scopes".
     */
    public function testJwtEnvelopeIsWrittenOverTheUserClaims(): void
    {
        [$payload] = $this->serialise($this->mock(
            subject: 'resolved-subject',
            userClaims: [
                ClaimsEnum::Iss->value => 'https://attacker.example.org',
                ClaimsEnum::Sub->value => 'someone-else',
                ClaimsEnum::Aud->value => 'other-client',
                ClaimsEnum::ClientId->value => 'other-client',
                ClaimsEnum::Scope->value => 'admin',
                'scopes' => ['admin'],
                ClaimsEnum::Jti->value => 'forged',
                ClaimsEnum::Exp->value => 0,
            ],
        ));

        $this->assertSame('https://op.example.org', $payload[ClaimsEnum::Iss->value]);
        $this->assertSame('resolved-subject', $payload[ClaimsEnum::Sub->value]);
        $this->assertSame($this->clientId, $payload[ClaimsEnum::Aud->value]);
        $this->assertSame($this->clientId, $payload[ClaimsEnum::ClientId->value]);
        $this->assertSame('openid profile', $payload[ClaimsEnum::Scope->value]);
        $this->assertSame(array_values($this->scopes), $payload['scopes']);
        $this->assertSame($this->id, $payload[ClaimsEnum::Jti->value]);
        $this->assertSame($this->expiryDateTime->getTimestamp(), $payload[ClaimsEnum::Exp->value]);
    }


    /**
     * Minted through the library's JwtAccessTokenFactory, the token is what its JwtAccessToken parses: the
     * "typ" header is "at+jwt" (RFC 9068 section 2.1, written by the factory, not by this entity), and the
     * envelope comes back through the profile's typed getters.
     */
    public function testMintsAJwtAccessTokenTheLibraryReadsBack(): void
    {
        [$oAuth2, $moduleConfig] = $this->realOAuth2AndModuleConfig();

        $token = (new AccessTokenEntity(
            $this->id,
            $this->clientEntityStub,
            $this->scopes,
            $this->expiryDateTime,
            $oAuth2,
            $moduleConfig,
            $this->userId,
            subject: 'resolved-subject',
            userClaims: ['voperson_id' => 'v1@example.org', 'eduperson_entitlement' => ['e1', 'e2']],
        ))->toString();

        $jwtAccessToken = $oAuth2->jwtAccessTokenFactory()->fromToken($token);

        $this->assertSame(JwtTypesEnum::AtJwt->value, $jwtAccessToken->getType());
        $this->assertSame('kid123', $jwtAccessToken->getKeyId());
        $this->assertSame('https://op.example.org', $jwtAccessToken->getIssuer());
        $this->assertSame('resolved-subject', $jwtAccessToken->getSubject());
        $this->assertSame([$this->clientId], $jwtAccessToken->getAudience());
        $this->assertSame($this->clientId, $jwtAccessToken->getClientId());
        $this->assertSame($this->id, $jwtAccessToken->getJwtId());
        $this->assertSame(['openid', 'profile'], $jwtAccessToken->getScopes());
        $this->assertSame($this->expiryDateTime->getTimestamp(), $jwtAccessToken->getExpirationTime());
        $this->assertSame('v1@example.org', $jwtAccessToken->getPayloadClaim('voperson_id'));
        $this->assertSame(['e1', 'e2'], $jwtAccessToken->getPayloadClaim('eduperson_entitlement'));
    }


    /**
     * The factory validates the payload against the profile before signing, so a user claim which takes a
     * name the profile gives a shape to, with a value of another shape, stops the token at minting: "groups"
     * is a list (RFC 9068 section 2.2.3.1). ClaimTranslatorExtractorFactory refuses such a configuration
     * first; this is the second line.
     */
    public function testRefusesToMintAPayloadTheProfileDoesNotAllow(): void
    {
        [$oAuth2, $moduleConfig] = $this->realOAuth2AndModuleConfig();

        $accessTokenEntity = new AccessTokenEntity(
            $this->id,
            $this->clientEntityStub,
            $this->scopes,
            $this->expiryDateTime,
            $oAuth2,
            $moduleConfig,
            $this->userId,
            userClaims: [ClaimsEnum::Groups->value => 'admins'],
        );

        $this->expectException(JwsException::class);
        $this->expectExceptionMessage('Value is not a list');

        $accessTokenEntity->toString();
    }
}
