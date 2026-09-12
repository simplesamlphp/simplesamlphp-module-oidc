<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\IssuerStateEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\CredentialOfferUriFactory;
use SimpleSAML\Module\oidc\Factories\EmailFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\IssuerStateEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\UserIdentifierResolver;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\VerifiableCredentials;
use SimpleSAML\OpenID\VerifiableCredentials\TxCode;
use SimpleSAML\Utils\Attributes;
use SimpleSAML\Utils\EMail;
use SimpleSAML\Utils\Random;
use Stringable;

#[CoversClass(CredentialOfferUriFactory::class)]
#[UsesClass(AuthCodeEntity::class)]
#[UsesClass(IssuerStateEntity::class)]
#[UsesClass(ScopeEntity::class)]
#[UsesClass(UserEntity::class)]
#[AllowMockObjectsWithoutExpectations]
class CredentialOfferUriFactoryTest extends TestCase
{
    protected const string PRE_AUTHORIZED_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';


    protected ModuleConfig&MockObject $moduleConfigMock;

    protected SspBridge&MockObject $sspBridgeMock;

    protected Utils&MockObject $utilsMock;

    protected Random&MockObject $randomMock;

    protected AuthCodeRepository&MockObject $authCodeRepositoryMock;

    protected AuthCodeEntityFactory&MockObject $authCodeEntityFactoryMock;

    protected ClientRepository&MockObject $clientRepositoryMock;

    protected ClientEntity&MockObject $clientMock;

    protected LoggerService&MockObject $loggerServiceMock;

    protected UserRepository&MockObject $userRepositoryMock;

    protected UserEntityFactory&MockObject $userEntityFactoryMock;

    protected EmailFactory&MockObject $emailFactoryMock;

    protected EMail&MockObject $emailMock;

    protected IssuerStateEntityFactory&MockObject $issuerStateEntityFactoryMock;

    protected IssuerStateRepository&MockObject $issuerStateRepositoryMock;

    protected UserIdentifierResolver&MockObject $userIdentifierResolverMock;

    /** @var list<array{level: string, message: string, context: array}> */
    protected array $logRecords = [];

    /**
     * The parameters of each AuthCodeEntityFactory::fromData() call as the method sees them, defaults
     * filled in for the arguments not passed; one entry per call.
     *
     * @var list<array<string, mixed>>
     */
    protected array $authCodeArguments = [];


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciCredentialConfigurationIdsSupported')
            ->willReturn(['credential-configuration', 'other-configuration']);
        $this->moduleConfigMock->method('getUserIdentifierAttributes')->willReturn(['uid']);
        $this->moduleConfigMock->method('getDefaultUsersEmailAttributeName')->willReturn('mail');
        $this->moduleConfigMock->method('getAuthCodeDuration')->willReturn(new DateInterval('PT10M'));
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://issuer.example.org');

        $this->randomMock = $this->createMock(Random::class);
        $this->randomMock->method('generateID')->willReturn('pre-authorized-code-secret');
        $this->utilsMock = $this->createMock(Utils::class);
        // Resolved at call time, so a test may swap in a Random of its own after setUp().
        $this->utilsMock->method('random')->willReturnCallback(fn (): Random => $this->randomMock);
        // The real one, so that reading the email attribute behaves as it does in SimpleSAMLphp.
        $this->utilsMock->method('attributes')->willReturn(new Attributes());
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->sspBridgeMock->method('utils')->willReturn($this->utilsMock);

        $this->clientMock = $this->createMock(ClientEntity::class);
        $this->clientMock->method('getIdentifier')->willReturn('vci-client');
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->clientRepositoryMock->method('getGenericForVci')->willReturn($this->clientMock);

        $this->userIdentifierResolverMock = $this->createMock(UserIdentifierResolver::class);
        $this->userIdentifierResolverMock->method('resolve')->willReturn('user-1');

        $this->userRepositoryMock = $this->createMock(UserRepository::class);
        $this->userEntityFactoryMock = $this->createMock(UserEntityFactory::class);
        $this->userEntityFactoryMock->method('fromData')->willReturnCallback(
            fn (string $identifier, array $claims = []): UserEntity => new UserEntity(
                $identifier,
                new DateTimeImmutable(),
                new DateTimeImmutable(),
                $claims,
            ),
        );

        $this->authCodeEntityFactoryMock = $this->createMock(AuthCodeEntityFactory::class);
        $this->authCodeEntityFactoryMock->method('fromData')
            ->willReturnCallback($this->buildAuthCodeRecordingArguments(...));
        $this->authCodeRepositoryMock = $this->createMock(AuthCodeRepository::class);

        $this->emailMock = $this->createMock(EMail::class);
        $this->emailFactoryMock = $this->createMock(EmailFactory::class);

        $this->issuerStateEntityFactoryMock = $this->createMock(IssuerStateEntityFactory::class);
        $this->issuerStateEntityFactoryMock->method('buildNew')->willReturn($this->issuerState('issuer-state-value'));
        $this->issuerStateRepositoryMock = $this->createMock(IssuerStateRepository::class);

        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        foreach (['error', 'warning', 'info', 'debug'] as $level) {
            $this->captureLogs($level);
        }
    }


    public function testFallbackUserIdentifierDoesNotLogAttributesOrExceptionDetails(): void
    {
        $sensitiveAttributeValue = 'sensitive-user-attribute-value';
        $sensitiveExceptionValue = 'sensitive-resolver-exception-value';
        $userAttributes = [
            'displayName' => [$sensitiveAttributeValue],
            'privateClaim' => ['private-claim-value'],
        ];
        $this->userIdentifierResolverMock = $this->createMock(UserIdentifierResolver::class);
        $this->userIdentifierResolverMock->method('resolve')
            ->willThrowException(new RuntimeException($sensitiveExceptionValue));
        $this->userRepositoryMock->expects($this->once())->method('add');
        $this->authCodeRepositoryMock->expects($this->once())->method('persistNewAuthCode');

        $credentialOfferUri = $this->sut()->buildPreAuthorized(['credential-configuration'], $userAttributes);

        $this->assertStringStartsWith('openid-credential-offer://?', $credentialOfferUri);
        $logs = json_encode($this->logRecords, JSON_THROW_ON_ERROR);
        $this->assertStringNotContainsString($sensitiveAttributeValue, $logs);
        $this->assertStringNotContainsString('private-claim-value', $logs);
        $this->assertStringNotContainsString($sensitiveExceptionValue, $logs);
    }


    public function testByValueOfferSurvivesQueryParsing(): void
    {
        // Appended raw, the '&' would split the offer into a second query parameter and the '#' would
        // truncate it into a fragment, so a wallet would never see the whole issuer.
        $issuer = 'https://issuer.example.org/vci?tenant=a&region=b#frag';
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willReturn($issuer);

        $offer = $this->decodeOffer($this->sut()->buildForAuthorization(['credential-configuration']));

        $this->assertSame($issuer, $offer['credential_issuer']);
    }


    public function testByReferenceOfferSurvivesQueryParsing(): void
    {
        // An offer passed by reference is a URL which may carry a query string of its own.
        $offerUri = 'https://issuer.example.org/offers/1?tenant=a&format=jwt#frag';
        $factory = $this->sut();

        $parameters = $this->parseOfferUriQuery(
            (new ReflectionMethod($factory, 'buildUri'))->invoke($factory, $offerUri),
        );

        $this->assertSame(['credential_offer_uri'], array_keys($parameters));
        $this->assertSame($offerUri, $parameters['credential_offer_uri']);
    }


    public function testBuildTxCodeGeneratesFourDigitNumericCode(): void
    {
        $txCode = $this->sut()->buildTxCode('Enter the separately delivered code.');

        $this->assertMatchesRegularExpression('/^[0-9]{4}$/', $txCode->getCodeAsString());
    }


    public function testBuildTxCodePassesACodeAndDescriptionGivenToItThrough(): void
    {
        $sut = $this->sut();

        $numeric = $sut->buildTxCode('Enter the code.', 4711);
        $text = $sut->buildTxCode('Enter the letters.', 'A1B2');

        $this->assertSame(4711, $numeric->getCode());
        $this->assertSame('Enter the code.', $numeric->getDescription());
        $this->assertSame('A1B2', $text->getCode());
        $this->assertSame('Enter the letters.', $text->getDescription());
    }


    public function testOffersForAuthorizationTheIssuerStateItPersisted(): void
    {
        $persisted = null;
        $this->issuerStateRepositoryMock->expects($this->once())->method('persist')
            ->willReturnCallback(function (IssuerStateEntity $issuerState) use (&$persisted): void {
                $persisted = $issuerState;
            });

        $offer = $this->decodeOffer(
            $this->sut()->buildForAuthorization(['credential-configuration', 'other-configuration']),
        );

        $this->assertInstanceOf(IssuerStateEntity::class, $persisted);
        $this->assertSame('issuer-state-value', $persisted->getValue());
        $this->assertSame([
            'credential_issuer' => 'https://issuer.example.org',
            'credential_configuration_ids' => ['credential-configuration', 'other-configuration'],
            'grants' => [
                'authorization_code' => [
                    'issuer_state' => 'issuer-state-value',
                ],
            ],
        ], $offer);
        $this->assertSame([], $this->logged('warning'));
        $this->assertSame([], $this->logged('error'));
    }


    public function testRetriesWithAFreshIssuerStateWhenPersistingOneFails(): void
    {
        $this->issuerStateEntityFactoryMock = $this->createMock(IssuerStateEntityFactory::class);
        $this->issuerStateEntityFactoryMock->expects($this->exactly(2))->method('buildNew')
            ->willReturnOnConsecutiveCalls($this->issuerState('state-1'), $this->issuerState('state-2'));
        $persisted = [];
        $this->issuerStateRepositoryMock->expects($this->exactly(2))->method('persist')
            ->willReturnCallback(function (IssuerStateEntity $issuerState) use (&$persisted): void {
                $persisted[] = $issuerState->getValue();
                if ($issuerState->getValue() === 'state-1') {
                    throw new RuntimeException('SQLSTATE[23000]: Integrity constraint violation');
                }
            });

        $offer = $this->decodeOffer($this->sut()->buildForAuthorization(['credential-configuration']));

        $this->assertSame(['state-1', 'state-2'], $persisted);
        $this->assertSame('state-2', $offer['grants']['authorization_code']['issuer_state']);
        $this->assertSame(
            ['Failed to generate Issuer State: SQLSTATE[23000]: Integrity constraint violation'],
            $this->logged('warning'),
        );
        $this->assertSame([], $this->logged('error'));
    }


    public function testGivesUpOnTheIssuerStateAfterThreeFailedAttempts(): void
    {
        $this->issuerStateEntityFactoryMock = $this->createMock(IssuerStateEntityFactory::class);
        $this->issuerStateEntityFactoryMock->expects($this->exactly(3))->method('buildNew')
            ->willReturnOnConsecutiveCalls(
                $this->issuerState('state-1'),
                $this->issuerState('state-2'),
                $this->issuerState('state-3'),
            );
        $failures = [];
        $this->issuerStateRepositoryMock->expects($this->exactly(3))->method('persist')
            ->willReturnCallback(function (IssuerStateEntity $issuerState) use (&$failures): void {
                $failures[] = $failure = new RuntimeException('cannot persist ' . $issuerState->getValue());
                throw $failure;
            });

        try {
            $this->sut()->buildForAuthorization(['credential-configuration']);
        } catch (OpenIdException $e) {
            $this->assertSame('Failed to generate issuer state.', $e->getMessage());
            $this->assertSame($failures[2], $e->getPrevious());
            $this->assertSame([
                'Failed to generate Issuer State: cannot persist state-1',
                'Failed to generate Issuer State: cannot persist state-2',
            ], $this->logged('warning'));
            $this->assertSame(
                ['All attempts to generate Issuer State failed: cannot persist state-3'],
                $this->logged('error'),
            );
            return;
        }

        $this->fail('An OpenIdException was expected.');
    }


    #[DataProvider('unofferableCredentialConfigurationProvider')]
    public function testRefusesAPreAuthorizedOfferForCredentialConfigurationsItCannotOffer(
        array $requested,
        string $message,
    ): void {
        $this->expectNothingWritten();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage($message);

        $this->sut()->buildPreAuthorized($requested, ['uid' => ['user-1']]);
    }


    public static function unofferableCredentialConfigurationProvider(): array
    {
        return [
            'none named' => [[], 'No credential configuration IDs provided.'],
            'one it does not support' => [
                ['unknown-configuration'],
                'Unsupported credential configuration IDs provided.',
            ],
            'a supported one beside an unsupported one' => [
                ['credential-configuration', 'unknown-configuration'],
                'Unsupported credential configuration IDs provided.',
            ],
        ];
    }


    public function testRefusesAnyPreAuthorizedOfferWhenNoCredentialConfigurationIsConfigured(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciCredentialConfigurationIdsSupported')->willReturn([]);
        $this->expectNothingWritten();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('No credential configuration IDs configured.');

        $this->sut()->buildPreAuthorized(['credential-configuration'], ['uid' => ['user-1']]);
    }


    public function testBindsThePreAuthorizedCodeToTheResolvedUserAndOffersIt(): void
    {
        $userAttributes = [
            'uid' => ['user-1'],
            'mail' => ['user@example.org'],
            'displayName' => ['Example User'],
        ];
        $this->userIdentifierResolverMock = $this->createMock(UserIdentifierResolver::class);
        $this->userIdentifierResolverMock->expects($this->once())->method('resolve')
            ->with(['uid'], $userAttributes)
            ->willReturn('user-1');
        $this->userRepositoryMock->expects($this->once())->method('getUserEntityByIdentifier')
            ->with('user-1')
            ->willReturn(null);
        $written = null;
        $this->userRepositoryMock->expects($this->once())->method('add')
            ->willReturnCallback(function (UserEntity $userEntity) use (&$written): void {
                $written = $userEntity;
            });
        $this->userRepositoryMock->expects($this->never())->method('update');
        $persisted = null;
        $this->authCodeRepositoryMock->expects($this->once())->method('persistNewAuthCode')
            ->willReturnCallback(function (AuthCodeEntity $authCode) use (&$persisted): void {
                $persisted = $authCode;
            });
        $this->emailFactoryMock->expects($this->never())->method('build');
        $before = time();

        $credentialOfferUri = $this->sut()->buildPreAuthorized(
            ['credential-configuration', 'other-configuration'],
            $userAttributes,
        );

        $this->assertInstanceOf(UserEntity::class, $written);
        $this->assertSame('user-1', $written->getIdentifier());
        $this->assertSame($userAttributes, $written->getClaims());

        $this->assertCount(1, $this->authCodeArguments);
        $arguments = $this->authCodeArguments[0];
        $this->assertEqualsWithDelta($before + 600, $arguments['expiryDateTime']->getTimestamp(), 5);
        unset($arguments['expiryDateTime']);
        $arguments['scopes'] = array_map(
            fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $arguments['scopes'],
        );
        $this->assertSame([
            'id' => 'pre-authorized-code-secret',
            'client' => $this->clientMock,
            'scopes' => ['openid', 'credential-configuration', 'other-configuration'],
            'userIdentifier' => 'user-1',
            'redirectUri' => 'openid-credential-offer://',
            'nonce' => null,
            'issuerState' => null,
            'isRevoked' => false,
            'flowTypeEnum' => FlowTypeEnum::VciPreAuthorizedCode,
            'txCode' => null,
            'authorizationDetails' => null,
            'boundClientId' => null,
            'boundRedirectUri' => null,
        ], $arguments);
        $this->assertInstanceOf(AuthCodeEntity::class, $persisted);
        $this->assertSame('pre-authorized-code-secret', $persisted->getIdentifier());

        $this->assertSame([
            'credential_issuer' => 'https://issuer.example.org',
            'credential_configuration_ids' => ['credential-configuration', 'other-configuration'],
            'grants' => [
                self::PRE_AUTHORIZED_GRANT => [
                    'pre-authorized_code' => 'pre-authorized-code-secret',
                ],
            ],
        ], $this->decodeOffer($credentialOfferUri));
        $this->assertSame([], $this->logged('warning'));
        $this->assertSame([], $this->logged('error'));
    }


    /**
     * The record written for a user already known is the one just built from the attributes presented,
     * not the one found; only the choice between add and update depends on the lookup.
     */
    public function testUpdatesAUserItAlreadyKnowsRatherThanAddingAgain(): void
    {
        $userAttributes = ['uid' => ['user-1'], 'displayName' => ['Renamed User']];
        $known = new UserEntity(
            'user-1',
            new DateTimeImmutable('-1 day'),
            new DateTimeImmutable('-1 day'),
            ['uid' => ['user-1'], 'displayName' => ['Example User']],
        );
        $this->userRepositoryMock->method('getUserEntityByIdentifier')->with('user-1')->willReturn($known);
        $updated = null;
        $this->userRepositoryMock->expects($this->once())->method('update')
            ->willReturnCallback(
                function (UserEntity $userEntity, ?DateTimeImmutable $updatedAt = null) use (&$updated): void {
                    $updated = $userEntity;
                },
            );
        $this->userRepositoryMock->expects($this->never())->method('add');

        $this->sut()->buildPreAuthorized(['credential-configuration'], $userAttributes);

        $this->assertInstanceOf(UserEntity::class, $updated);
        $this->assertNotSame($known, $updated);
        $this->assertSame('user-1', $updated->getIdentifier());
        $this->assertSame($userAttributes, $updated->getClaims());
        $this->assertSame('user-1', $this->authCodeArguments[0]['userIdentifier']);
    }


    /**
     * With no identifier attribute to go on, the user is identified by a hash of the attributes
     * themselves, which has to come out the same however the attributes happen to be ordered.
     */
    public function testFallsBackToAnOrderIndependentAttributeHashWhenNoUserIdentifierResolves(): void
    {
        $this->userIdentifierResolverMock = $this->createMock(UserIdentifierResolver::class);
        $this->userIdentifierResolverMock->method('resolve')->willReturn(null);
        $attributes = [
            'displayName' => ['Example User'],
            'eduPersonAffiliation' => ['staff', 'member'],
        ];
        $reordered = [
            'eduPersonAffiliation' => ['member', 'staff'],
            'displayName' => ['Example User'],
        ];
        $someoneElse = [
            'displayName' => ['Someone Else'],
            'eduPersonAffiliation' => ['staff', 'member'],
        ];
        $lookedUp = [];
        $this->userRepositoryMock->expects($this->exactly(3))->method('getUserEntityByIdentifier')
            ->willReturnCallback(function (string $identifier) use (&$lookedUp): ?UserEntity {
                $lookedUp[] = $identifier;
                return null;
            });
        $sut = $this->sut();

        $sut->buildPreAuthorized(['credential-configuration'], $attributes);
        $sut->buildPreAuthorized(['credential-configuration'], $reordered);
        $sut->buildPreAuthorized(['credential-configuration'], $someoneElse);

        $expected = 'vci_credential_offer_preauthz_' . hash('sha256', serialize([
            'displayName' => ['Example User'],
            'eduPersonAffiliation' => ['member', 'staff'],
        ]));
        $identifiers = array_column($this->authCodeArguments, 'userIdentifier');
        $this->assertSame([$expected, $expected], array_slice($identifiers, 0, 2));
        $this->assertNotSame($expected, $identifiers[2]);
        $this->assertStringStartsWith('vci_credential_offer_preauthz_', $identifiers[2]);
        $this->assertSame($identifiers, $lookedUp);
        $fallingBack = [
            'Could not extract user identifier from credential-offer attributes.',
            'Falling back to user attributes hash for user identifier.',
        ];
        $this->assertSame([...$fallingBack, ...$fallingBack, ...$fallingBack], $this->logged('warning'));
        $this->assertSame(
            array_fill(0, 3, 'Generated user identifier based on credential-offer attributes.'),
            $this->logged('info'),
        );
        $this->assertSame([], $this->logged('error'));
    }


    /**
     * The transaction code travels out of band: it reaches the wallet holder by email and the
     * pre-authorized code record, and the offer itself carries only its shape.
     */
    public function testSendsTheTransactionCodeByEmailAndKeepsItOutOfTheOffer(): void
    {
        $userAttributes = ['uid' => ['user-1'], 'mail' => ['user@example.org']];
        $this->emailFactoryMock->expects($this->once())->method('build')
            ->with('Your one-time code', null, 'user@example.org', 'mailtxt.twig', 'mailhtml.twig')
            ->willReturn($this->emailMock);
        $this->emailMock->expects($this->once())->method('setText')
            ->with('Use the following code to complete the transaction.');
        $emailed = null;
        $this->emailMock->expects($this->once())->method('setData')
            ->willReturnCallback(function (array $data) use (&$emailed): void {
                $emailed = $data;
            });
        $this->emailMock->expects($this->once())->method('send');
        $this->authCodeRepositoryMock->expects($this->once())->method('persistNewAuthCode');

        $credentialOfferUri = $this->sut()->buildPreAuthorized(
            ['credential-configuration'],
            $userAttributes,
            useTxCode: true,
        );

        $code = $this->authCodeArguments[0]['txCode'];
        $this->assertIsString($code);
        $this->assertMatchesRegularExpression('/^[0-9]{4}$/', $code);
        $this->assertSame(['Transaction Code' => $code], $emailed);
        $this->assertSame([
            'credential_issuer' => 'https://issuer.example.org',
            'credential_configuration_ids' => ['credential-configuration'],
            'grants' => [
                self::PRE_AUTHORIZED_GRANT => [
                    'pre-authorized_code' => 'pre-authorized-code-secret',
                    'tx_code' => [
                        'input_mode' => 'numeric',
                        'length' => 4,
                        'description' => 'Please provide the one-time code that was sent to e-mail user@example.org',
                    ],
                ],
            ],
        ], $this->decodeOffer($credentialOfferUri));
        // Digits are never percent-encoded, so the raw URI is the only shape the code could take.
        $this->assertStringNotContainsString($code, $credentialOfferUri);
        $this->assertSame(['Generated transaction code for delivery by email.'], $this->logged('debug'));
        $this->assertSame([], $this->logged('warning'));
        $this->assertSame([], $this->logged('error'));
    }


    public function testTakesTheEmailFromTheAttributeItIsToldRatherThanTheDefault(): void
    {
        $userAttributes = [
            'uid' => ['user-1'],
            'mail' => ['default@example.org'],
            'emailAddress' => ['told@example.org'],
        ];
        $this->emailFactoryMock->expects($this->once())->method('build')
            ->with('Your one-time code', null, 'told@example.org', 'mailtxt.twig', 'mailhtml.twig')
            ->willReturn($this->emailMock);

        $offer = $this->decodeOffer($this->sut()->buildPreAuthorized(
            ['credential-configuration'],
            $userAttributes,
            useTxCode: true,
            userEmailAttributeName: 'emailAddress',
        ));

        $this->assertSame(
            'Please provide the one-time code that was sent to e-mail told@example.org',
            $offer['grants'][self::PRE_AUTHORIZED_GRANT]['tx_code']['description'],
        );
    }


    public function testCannotOfferATransactionCodeWithoutAnEmailToSendItTo(): void
    {
        $this->authCodeRepositoryMock->expects($this->never())->method('persistNewAuthCode');
        $this->emailFactoryMock->expects($this->never())->method('build');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            "Could not extract user email from user attributes: No such attribute 'mail' found.",
        );

        $this->sut()->buildPreAuthorized(['credential-configuration'], ['uid' => ['user-1']], useTxCode: true);
    }


    public function testRetriesWithAFreshCodeWhenPersistingOneFails(): void
    {
        $this->randomMock = $this->createMock(Random::class);
        $this->randomMock->expects($this->exactly(2))->method('generateID')
            ->willReturnOnConsecutiveCalls('code-1', 'code-2');
        $persisted = [];
        $this->authCodeRepositoryMock->expects($this->exactly(2))->method('persistNewAuthCode')
            ->willReturnCallback(function (AuthCodeEntity $authCode) use (&$persisted): void {
                $persisted[] = $authCode->getIdentifier();
                if ($authCode->getIdentifier() === 'code-1') {
                    throw new RuntimeException('SQLSTATE[23000]: Integrity constraint violation');
                }
            });
        // The user is written once, before the loop, however many attempts the code takes.
        $this->userRepositoryMock->expects($this->once())->method('add');
        $this->userRepositoryMock->expects($this->never())->method('update');

        $offer = $this->decodeOffer(
            $this->sut()->buildPreAuthorized(['credential-configuration'], ['uid' => ['user-1']]),
        );

        $this->assertSame(['code-1', 'code-2'], $persisted);
        $this->assertSame('code-2', $offer['grants'][self::PRE_AUTHORIZED_GRANT]['pre-authorized_code']);
        $this->assertSame(
            ['Failed to generate Authorization Code ID: SQLSTATE[23000]: Integrity constraint violation'],
            $this->logged('warning'),
        );
        $this->assertSame([], $this->logged('error'));
    }


    public function testGivesUpOnTheCodeAfterThreeFailedAttempts(): void
    {
        $this->randomMock = $this->createMock(Random::class);
        $this->randomMock->expects($this->exactly(3))->method('generateID')
            ->willReturnOnConsecutiveCalls('code-1', 'code-2', 'code-3');
        $failures = [];
        $this->authCodeRepositoryMock->expects($this->exactly(3))->method('persistNewAuthCode')
            ->willReturnCallback(function (AuthCodeEntity $authCode) use (&$failures): void {
                $failures[] = $failure = new RuntimeException('cannot persist ' . $authCode->getIdentifier());
                throw $failure;
            });

        try {
            $this->sut()->buildPreAuthorized(['credential-configuration'], ['uid' => ['user-1']]);
        } catch (OpenIdException $e) {
            $this->assertSame('Failed to generate Authorization Code.', $e->getMessage());
            $this->assertSame($failures[2], $e->getPrevious());
            $this->assertSame([
                'Failed to generate Authorization Code ID: cannot persist code-1',
                'Failed to generate Authorization Code ID: cannot persist code-2',
            ], $this->logged('warning'));
            $this->assertSame(
                ['All attempts to generate Authorization Code failed: cannot persist code-3'],
                $this->logged('error'),
            );
            return;
        }

        $this->fail('An OpenIdException was expected.');
    }


    public function testTakesTheFirstOfSeveralEmailValues(): void
    {
        $email = $this->sut()->getUserEmail('mail', [
            'mail' => ['first@example.org', 'second@example.org'],
        ]);

        $this->assertSame('first@example.org', $email);
    }


    /**
     * The wording after the prefix is SimpleSAMLphp's, so only the prefix and the attribute named are pinned.
     */
    public function testRefusesAnEmailAttributeItCannotRead(): void
    {
        try {
            $this->sut()->getUserEmail('emailAddress', ['mail' => ['user@example.org']]);
        } catch (RuntimeException $e) {
            $this->assertStringStartsWith('Could not extract user email from user attributes: ', $e->getMessage());
            $this->assertStringContainsString("'emailAddress'", $e->getMessage());
            return;
        }

        $this->fail('A RuntimeException was expected.');
    }


    public function testRefusesAnEmailValueWhichIsNotAString(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('User email attribute value is not a string.');

        $this->sut()->getUserEmail('mail', ['mail' => [42]]);
    }


    #[DataProvider('emailSubjectProvider')]
    public function testSendsTheCodeInAnEmailWithTheSubjectGivenOrTheDefault(?string $subject, string $expected): void
    {
        $txCode = new TxCode(4711, 'Enter the code.');
        $this->emailFactoryMock->expects($this->once())->method('build')
            ->with($expected, null, 'user@example.org', 'mailtxt.twig', 'mailhtml.twig')
            ->willReturn($this->emailMock);
        $this->emailMock->expects($this->once())->method('setText')
            ->with('Use the following code to complete the transaction.');
        $this->emailMock->expects($this->once())->method('setData')
            ->with(['Transaction Code' => '4711']);
        $this->emailMock->expects($this->once())->method('send');

        $this->sut()->sendTxCodeByEmail($txCode, 'user@example.org', $subject);
    }


    public static function emailSubjectProvider(): array
    {
        return [
            'the default' => [null, 'Your one-time code'],
            'the one given' => ['Your ACME wallet code', 'Your ACME wallet code'],
        ];
    }


    protected function sut(): CredentialOfferUriFactory
    {
        return new CredentialOfferUriFactory(
            new VerifiableCredentials(),
            $this->moduleConfigMock,
            $this->sspBridgeMock,
            $this->authCodeRepositoryMock,
            $this->authCodeEntityFactoryMock,
            $this->clientRepositoryMock,
            $this->loggerServiceMock,
            $this->userRepositoryMock,
            $this->userEntityFactoryMock,
            $this->emailFactoryMock,
            $this->issuerStateEntityFactoryMock,
            $this->issuerStateRepositoryMock,
            $this->userIdentifierResolverMock,
        );
    }


    /**
     * Stands in for AuthCodeEntityFactory::fromData() with the same signature, so that named
     * arguments land where the real one would put them; records them and builds the real entity.
     */
    protected function buildAuthCodeRecordingArguments(
        string $id,
        OAuth2ClientEntityInterface $client,
        array $scopes,
        DateTimeImmutable $expiryDateTime,
        ?string $userIdentifier = null,
        ?string $redirectUri = null,
        ?string $nonce = null,
        ?string $issuerState = null,
        bool $isRevoked = false,
        ?FlowTypeEnum $flowTypeEnum = null,
        ?string $txCode = null,
        ?array $authorizationDetails = null,
        ?string $boundClientId = null,
        ?string $boundRedirectUri = null,
    ): AuthCodeEntity {
        $this->authCodeArguments[] = get_defined_vars();

        return new AuthCodeEntity(
            $id,
            $client,
            $scopes,
            $expiryDateTime,
            $userIdentifier,
            $redirectUri,
            $nonce,
            $isRevoked,
            $flowTypeEnum,
            $txCode,
            $authorizationDetails,
            $boundClientId,
            $boundRedirectUri,
            $issuerState,
        );
    }


    protected function issuerState(string $value): IssuerStateEntity
    {
        $createdAt = new DateTimeImmutable('2026-06-24T00:00:00+00:00');

        return new IssuerStateEntity($value, $createdAt, $createdAt->add(new DateInterval('PT5M')));
    }


    protected function expectNothingWritten(): void
    {
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->clientRepositoryMock->expects($this->never())->method('getGenericForVci');
        $this->userRepositoryMock->expects($this->never())->method('add');
        $this->userRepositoryMock->expects($this->never())->method('update');
        $this->authCodeRepositoryMock->expects($this->never())->method('persistNewAuthCode');
        $this->issuerStateRepositoryMock->expects($this->never())->method('persist');
        $this->emailFactoryMock->expects($this->never())->method('build');
    }


    /**
     * Parse the query of an offer URI back into parameters. parse_url() rejects the
     * openid-credential-offer:// scheme outright, so the prefix is stripped by hand.
     *
     * @return array<string, string>
     */
    protected function parseOfferUriQuery(string $credentialOfferUri): array
    {
        $prefix = 'openid-credential-offer://?';
        $this->assertStringStartsWith($prefix, $credentialOfferUri);

        parse_str(substr($credentialOfferUri, strlen($prefix)), $parameters);

        /** @var array<string, string> $parameters */
        return $parameters;
    }


    /**
     * The offer carried by value, decoded; asserts it is the only query parameter.
     *
     * @return array<string, mixed>
     */
    protected function decodeOffer(string $credentialOfferUri): array
    {
        $parameters = $this->parseOfferUriQuery($credentialOfferUri);
        $this->assertSame(['credential_offer'], array_keys($parameters));

        return json_decode($parameters['credential_offer'], true, 512, JSON_THROW_ON_ERROR);
    }


    protected function captureLogs(string $level): void
    {
        $this->loggerServiceMock->method($level)->willReturnCallback(
            function (string|Stringable $message, array $context = []) use ($level): void {
                $this->logRecords[] = ['level' => $level, 'message' => (string)$message, 'context' => $context];
            },
        );
    }


    /**
     * @return list<string>
     */
    protected function logged(string $level): array
    {
        return array_values(array_map(
            fn (array $record): string => $record['message'],
            array_filter($this->logRecords, fn (array $record): bool => $record['level'] === $level),
        ));
    }
}
