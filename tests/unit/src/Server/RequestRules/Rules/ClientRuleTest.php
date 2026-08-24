<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\Module\oidc\Utils\FederationParticipationValidator;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Core\RequestObject as ConnectRequestObject;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Exceptions\TrustChainResolutionBudgetException;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\EntityStatement;
use SimpleSAML\OpenID\Federation\RequestObject as FederationRequestObject;
use SimpleSAML\OpenID\Federation\TrustChain;
use SimpleSAML\OpenID\Federation\TrustChainBag;
use SimpleSAML\OpenID\Federation\TrustChainResolver;
use SimpleSAML\OpenID\Helpers as OpenIdHelpers;
use SimpleSAML\OpenID\Helpers\Json;
use SimpleSAML\OpenID\RequestObject\RequestObjectBag;
use SimpleSAML\OpenID\ValueAbstracts\JwksClaim;
use Stringable;
use Throwable;

/**
 * Resolution of the client an authorization request is speaking for.
 *
 * Everything downstream -- redirect URI matching, PKCE, scopes, and ultimately who the issued token is for --
 * trusts whatever this rule returns, so the interesting cases are the ones where it must refuse. Most of the
 * class is resolveFromFederation(), which registers a client out of a trust chain resolved over the network at
 * an endpoint reachable without authentication; each of its refusal paths is exercised here, and each asserts
 * that nothing was persisted rather than only that an exception came back.
 *
 * The collaborators are wired once, in setUp(), to the shape of a *successful* federation resolution, and each
 * test spoils exactly one thing. That keeps the refusal tests honest: if the case a test names stopped being
 * refused, the run would fall through to the success path and the missing exception would fail the test rather
 * than pass it. For the same reason the collaborators read mutable scenario properties through callbacks
 * instead of being re-stubbed per test -- a mock keeps the first matcher registered for a method, so a second
 * method() call on the same method would silently do nothing.
 */
#[CoversClass(ClientRule::class)]
#[UsesClass(Result::class)]
#[UsesClass(ResultBag::class)]
#[AllowMockObjectsWithoutExpectations]
class ClientRuleTest extends TestCase
{
    private const string CLIENT_ID = 'https://rp.example.org';

    private const string ISSUER = 'https://op.example.org';

    private const string TRUST_ANCHOR_ID = 'https://ta.example.org';

    private const string REQUEST_OBJECT_JTI = 'request-object-jti';

    private const string CACHE_KEY_REQUEST_OBJECT_JTI = 'request_object_jti';

    private const int TRUST_CHAIN_EXPIRATION = 1893456000;

    private const array CLIENT_METADATA = ['client_name' => 'Example RP'];

    private const array CLIENT_JWKS = ['keys' => [['kty' => 'RSA', 'kid' => 'client-key']]];

    private const array FEDERATION_JWKS = ['keys' => [['kty' => 'RSA', 'kid' => 'federation-key']]];

    private const array REQUEST_OBJECT_PAYLOAD = ['iss' => self::CLIENT_ID, 'scope' => 'openid'];


    private RequestParamsResolver&MockObject $requestParamsResolverMock;

    private ClientRepository&MockObject $clientRepositoryMock;

    private ModuleConfig&MockObject $moduleConfigMock;

    private ClientEntityFactory&MockObject $clientEntityFactoryMock;

    private Federation&MockObject $federationMock;

    private JwksResolver&MockObject $jwksResolverMock;

    private FederationParticipationValidator&MockObject $participationValidatorMock;

    private LoggerService&MockObject $loggerServiceMock;

    private FederationCache&MockObject $federationCacheMock;

    private ServerRequestInterface&MockObject $requestMock;

    private ResponseModeInterface&MockObject $responseModeMock;

    private RequestObjectBag&MockObject $requestObjectBagMock;

    private FederationRequestObject&MockObject $requestObjectMock;

    private TrustChainResolver&MockObject $trustChainResolverMock;

    private TrustChainBag&MockObject $trustChainBagMock;

    private TrustChain&MockObject $trustChainMock;

    private EntityStatement&MockObject $trustAnchorStatementMock;

    private EntityStatement&MockObject $leafStatementMock;

    private ClientEntityInterface&MockObject $registrationClientMock;

    private ClientEntityInterface&MockObject $genericVciClientMock;

    private ResultBag $resultBag;

    /** The scenario. Each test spoils one of these before calling the rule. */
    private ?FederationCache $federationCache = null;

    private ?string $clientIdParam = null;

    private array $serverParams = [];

    private ?ClientEntityInterface $storedClient = null;

    private bool $federationEnabled = false;

    private bool $isVciRequest = false;

    private bool $vciEnabled = false;

    private bool $vciAllowsNonRegisteredClients = false;

    private ?RequestObjectBag $requestObjectBag = null;

    private ConnectRequestObject|FederationRequestObject|null $resolvedRequestObject = null;

    private array $requestObjectAudience = [self::ISSUER];

    private string $requestObjectIssuer = self::CLIENT_ID;

    private bool $requestObjectJtiAlreadySeen = false;

    private ?Throwable $requestObjectSignatureFailure = null;

    private ?Throwable $trustChainResolutionFailure = null;

    private string $leafIssuer = self::CLIENT_ID;

    private ?string $localTrustAnchorJwksJson = null;

    private ?array $resolvedClientMetadata = self::CLIENT_METADATA;

    private ?Throwable $metadataResolutionFailure = null;

    private ?ClientEntityInterface $existingClient = null;

    private ?array $clientJwks = self::CLIENT_JWKS;

    private bool $participationLimitedByTrustMarks = false;

    private ?Throwable $trustMarkValidationFailure = null;

    private ?Throwable $cacheWriteFailure = null;

    /** What the collaborators were actually asked to do. */
    private ?string $lookedUpClientId = null;

    private bool $federationResolutionAttempted = false;

    private bool $genericVciClientRequested = false;

    private array $registrationArguments = [];

    private array $addedClients = [];

    private array $updatedClients = [];

    private array $cacheWrites = [];

    private bool $trustMarksValidated = false;

    private ?array $trustAnchorVerifiedWithJwks = null;

    private array $logs = [];


    protected function setUp(): void
    {
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->clientEntityFactoryMock = $this->createMock(ClientEntityFactory::class);
        $this->federationMock = $this->createMock(Federation::class);
        $this->jwksResolverMock = $this->createMock(JwksResolver::class);
        $this->participationValidatorMock = $this->createMock(FederationParticipationValidator::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->federationCacheMock = $this->createMock(FederationCache::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->responseModeMock = $this->createMock(ResponseModeInterface::class);
        $this->requestObjectBagMock = $this->createMock(RequestObjectBag::class);
        $this->requestObjectMock = $this->createMock(FederationRequestObject::class);
        $this->trustChainResolverMock = $this->createMock(TrustChainResolver::class);
        $this->trustChainBagMock = $this->createMock(TrustChainBag::class);
        $this->trustChainMock = $this->createMock(TrustChain::class);
        $this->trustAnchorStatementMock = $this->createMock(EntityStatement::class);
        $this->leafStatementMock = $this->createMock(EntityStatement::class);
        $this->registrationClientMock = $this->createMock(ClientEntityInterface::class);
        $this->genericVciClientMock = $this->createMock(ClientEntityInterface::class);

        $this->federationCache = $this->federationCacheMock;
        $this->requestObjectBag = $this->requestObjectBagMock;
        $this->resolvedRequestObject = $this->requestObjectMock;
        $this->resultBag = new ResultBag();

        $this->wireRequest();
        $this->wireConfig();
        $this->wireRepository();
        $this->wireFederation();
        $this->wireLogger();
    }


    private function wireRequest(): void
    {
        $this->requestMock->method('getServerParams')->willReturnCallback(fn(): array => $this->serverParams);

        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')
            ->willReturnCallback(fn(): ?string => $this->clientIdParam);

        $this->requestParamsResolverMock->method('isVciAuthorizationCodeRequest')
            ->willReturnCallback(fn(): bool => $this->isVciRequest);

        $this->requestParamsResolverMock->method('getRequestObjectBag')
            ->willReturnCallback(function (): ?RequestObjectBag {
                $this->federationResolutionAttempted = true;

                return $this->requestObjectBag;
            });
    }


    private function wireConfig(): void
    {
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->moduleConfigMock->method('getFederationTrustAnchorIds')->willReturn([self::TRUST_ANCHOR_ID]);
        $this->moduleConfigMock->method('getFederationEnabled')
            ->willReturnCallback(fn(): bool => $this->federationEnabled);
        $this->moduleConfigMock->method('getVciEnabled')->willReturnCallback(fn(): bool => $this->vciEnabled);
        $this->moduleConfigMock->method('getVciAllowNonRegisteredClients')
            ->willReturnCallback(fn(): bool => $this->vciAllowsNonRegisteredClients);
        $this->moduleConfigMock->method('getTrustAnchorJwksJson')
            ->willReturnCallback(fn(): ?string => $this->localTrustAnchorJwksJson);
        $this->moduleConfigMock->method('isFederationParticipationLimitedByTrustMarksFor')
            ->willReturnCallback(fn(): bool => $this->participationLimitedByTrustMarks);
    }


    private function wireRepository(): void
    {
        $this->clientRepositoryMock->method('getClientEntity')
            ->willReturnCallback(function (string $clientIdentifier): ?ClientEntityInterface {
                $this->lookedUpClientId = $clientIdentifier;

                return $this->storedClient;
            });

        $this->clientRepositoryMock->method('findById')
            ->willReturnCallback(fn(): ?ClientEntityInterface => $this->existingClient);

        $this->clientRepositoryMock->method('add')
            ->willReturnCallback(function (ClientEntityInterface $client): void {
                $this->addedClients[] = $client;
            });

        $this->clientRepositoryMock->method('update')
            ->willReturnCallback(function (ClientEntityInterface $client): void {
                $this->updatedClients[] = $client;
            });

        $this->clientRepositoryMock->method('getGenericForVci')
            ->willReturnCallback(function (): ClientEntityInterface {
                $this->genericVciClientRequested = true;

                return $this->genericVciClientMock;
            });

        $this->clientEntityFactoryMock->method('fromRegistrationData')
            ->willReturnCallback(function (mixed ...$arguments): ClientEntityInterface {
                $this->registrationArguments = $arguments;

                return $this->registrationClientMock;
            });
    }


    private function wireFederation(): void
    {
        $this->requestObjectBagMock->method('get')->willReturnCallback(
            fn(): ConnectRequestObject|FederationRequestObject|null => $this->resolvedRequestObject,
        );

        $this->requestObjectMock->method('getAudience')
            ->willReturnCallback(fn(): array => $this->requestObjectAudience);
        $this->requestObjectMock->method('getIssuer')->willReturnCallback(fn(): string => $this->requestObjectIssuer);
        $this->requestObjectMock->method('getJwtId')->willReturn(self::REQUEST_OBJECT_JTI);
        $this->requestObjectMock->method('getExpirationTime')->willReturn(self::TRUST_CHAIN_EXPIRATION);
        $this->requestObjectMock->method('getPayload')->willReturn(self::REQUEST_OBJECT_PAYLOAD);
        $this->requestObjectMock->method('verifyWithKeySet')->willReturnCallback(function (): void {
            if ($this->requestObjectSignatureFailure !== null) {
                throw $this->requestObjectSignatureFailure;
            }
        });

        $this->federationCacheMock->method('has')
            ->willReturnCallback(fn(): bool => $this->requestObjectJtiAlreadySeen);
        $this->federationCacheMock->method('set')
            ->willReturnCallback(function (mixed $value, mixed $ttl, string ...$keyElements): void {
                $this->cacheWrites[] = ['value' => $value, 'ttl' => $ttl, 'key' => $keyElements];

                if ($this->cacheWriteFailure !== null) {
                    throw $this->cacheWriteFailure;
                }
            });

        $openIdHelpersMock = $this->createMock(OpenIdHelpers::class);
        $openIdHelpersMock->method('json')->willReturn(new Json());
        $this->federationMock->method('helpers')->willReturn($openIdHelpersMock);
        $this->federationMock->method('trustChainResolver')->willReturn($this->trustChainResolverMock);

        $this->trustChainResolverMock->method('for')->willReturnCallback(function (): TrustChainBag {
            if ($this->trustChainResolutionFailure !== null) {
                throw $this->trustChainResolutionFailure;
            }

            return $this->trustChainBagMock;
        });
        $this->trustChainBagMock->method('getShortest')->willReturn($this->trustChainMock);

        $this->trustChainMock->method('getResolvedTrustAnchor')->willReturn($this->trustAnchorStatementMock);
        $this->trustChainMock->method('getResolvedLeaf')->willReturn($this->leafStatementMock);
        $this->trustChainMock->method('getResolvedExpirationTime')->willReturn(self::TRUST_CHAIN_EXPIRATION);
        $this->trustChainMock->method('getResolvedMetadata')->willReturnCallback(function (): ?array {
            if ($this->metadataResolutionFailure !== null) {
                throw $this->metadataResolutionFailure;
            }

            return $this->resolvedClientMetadata;
        });

        $this->trustAnchorStatementMock->method('getIssuer')->willReturn(self::TRUST_ANCHOR_ID);
        $this->trustAnchorStatementMock->method('verifyWithKeySet')
            ->willReturnCallback(function (?array $jwks = null): void {
                $this->trustAnchorVerifiedWithJwks = $jwks;
            });

        $jwksClaimMock = $this->createMock(JwksClaim::class);
        $jwksClaimMock->method('getValue')->willReturn(self::FEDERATION_JWKS);
        $this->leafStatementMock->method('getIssuer')->willReturnCallback(fn(): string => $this->leafIssuer);
        $this->leafStatementMock->method('getJwks')->willReturn($jwksClaimMock);

        $this->jwksResolverMock->method('forClient')->willReturnCallback(fn(): ?array => $this->clientJwks);

        $this->participationValidatorMock->method('byTrustMarksFor')->willReturnCallback(function (): void {
            $this->trustMarksValidated = true;

            if ($this->trustMarkValidationFailure !== null) {
                throw $this->trustMarkValidationFailure;
            }
        });
    }


    private function wireLogger(): void
    {
        foreach (['debug', 'warning', 'error'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string|Stringable $message, array $context = []) use ($level): void {
                    $this->logs[] = ['level' => $level, 'message' => (string)$message, 'context' => $context];
                },
            );
        }
    }

    // Identifying the client.

    public function testResolvesTheClientNamedByTheClientIdParameter(): void
    {
        $this->clientIdParam = 'client-123';
        $this->storedClient = $this->createMock(ClientEntityInterface::class);

        $result = $this->check();

        $this->assertSame('client-123', $this->lookedUpClientId);
        $this->assertSame($this->storedClient, $result?->getValue());
        // Downstream rules look the client up by this rule's own class name, so the key is part of the contract.
        $this->assertSame(ClientRule::class, $result?->getKey());
    }


    public function testFallsBackToTheBasicAuthUsernameWhenTheParameterIsAbsent(): void
    {
        // A confidential client authenticating at the token endpoint sends its identifier as the Basic auth
        // username rather than as a client_id parameter.
        $this->clientIdParam = null;
        $this->serverParams = ['PHP_AUTH_USER' => 'client-from-basic-auth'];
        $this->storedClient = $this->createMock(ClientEntityInterface::class);

        $this->check();

        $this->assertSame('client-from-basic-auth', $this->lookedUpClientId);
    }


    public function testPrefersTheClientIdParameterOverTheBasicAuthUsername(): void
    {
        $this->clientIdParam = 'client-from-parameter';
        $this->serverParams = ['PHP_AUTH_USER' => 'client-from-basic-auth'];
        $this->storedClient = $this->createMock(ClientEntityInterface::class);

        $this->check();

        $this->assertSame('client-from-parameter', $this->lookedUpClientId);
    }


    public function testRejectsARequestThatNamesNoClientAtAll(): void
    {
        $this->clientIdParam = null;
        $this->serverParams = [];

        try {
            $this->check();
            $this->fail('A request naming no client must be rejected.');
        } catch (OidcServerException $exception) {
            // invalid_request, not invalid_client: nothing was presented to authenticate in the first place.
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertStringContainsString('client_id', (string)$exception->getPayload()['error_description']);
        }

        $this->assertNull($this->lookedUpClientId);
    }


    public function testRefusesAnUnknownClientWhenNeitherFederationNorVciCanSupplyOne(): void
    {
        $this->clientIdParam = 'no-such-client';
        $this->storedClient = null;

        $this->assertClientIsRefused();

        // Federation is off, so the (unauthenticated, network-touching) resolution must not even be started.
        $this->assertFalse($this->federationResolutionAttempted);
        $this->assertFalse($this->genericVciClientRequested);
    }

    // The generic wallet client for Verifiable Credential issuance.

    public function testFallsBackToTheGenericWalletClientWhenEveryVciGateIsOpen(): void
    {
        $this->clientIdParam = 'unregistered-wallet';
        $this->storedClient = null;
        $this->isVciRequest = true;
        $this->vciEnabled = true;
        $this->vciAllowsNonRegisteredClients = true;

        $result = $this->check();

        $this->assertTrue($this->genericVciClientRequested);
        $this->assertSame($this->genericVciClientMock, $result?->getValue());
    }


    #[DataProvider('closedVciGateProvider')]
    public function testDoesNotFallBackToTheGenericWalletClientWhenAGateIsClosed(
        bool $isVciRequest,
        bool $vciEnabled,
        bool $allowsNonRegisteredClients,
    ): void {
        $this->clientIdParam = 'unregistered-wallet';
        $this->storedClient = null;
        $this->isVciRequest = $isVciRequest;
        $this->vciEnabled = $vciEnabled;
        $this->vciAllowsNonRegisteredClients = $allowsNonRegisteredClients;

        $this->assertClientIsRefused();

        $this->assertFalse($this->genericVciClientRequested);
    }


    /**
     * @return array<string,array{0:bool,1:bool,2:bool}>
     */
    public static function closedVciGateProvider(): array
    {
        // Exactly one gate closed per case, so each proves that gate alone is enough to refuse.
        return [
            'not a credential request' => [false, true, true],
            'verifiable credentials disabled' => [true, false, true],
            'non-registered clients not allowed' => [true, true, false],
        ];
    }

    // Resolving an unknown client from the federation.

    public function testRefusesWhenNoRequestObjectAccompaniesTheRequest(): void
    {
        $this->arrangeFederation();
        $this->requestObjectBag = null;

        $this->assertClientIsRefused();
    }


    public function testRefusesARequestObjectThatIsNotAFederationRequestObject(): void
    {
        // A plain OpenID Connect Core request object carries none of the federation claims this path needs,
        // so it must not be treated as one.
        $this->arrangeFederation();
        $this->resolvedRequestObject = $this->createMock(ConnectRequestObject::class);

        $this->assertClientIsRefused();
    }


    public function testRefusesARequestObjectAddressedToAnotherIssuer(): void
    {
        // Without this check a request object minted for a different OP could be replayed against this one.
        $this->arrangeFederation();
        $this->requestObjectAudience = ['https://another-op.example.org'];

        $this->assertClientIsRefused();
    }


    public function testRefusesAReplayedRequestObject(): void
    {
        $this->arrangeFederation();
        $this->requestObjectJtiAlreadySeen = true;

        $this->assertClientIsRefused();

        $this->logContaining('error', 'Request object reused');
    }


    public function testSkipsTheReplayCheckAndWarnsWhenNoFederationCacheIsConfigured(): void
    {
        // Without a cache there is nowhere to remember which JTIs have been seen. The rule deliberately keeps
        // working rather than refusing every client, so the warning is the only thing telling an operator that
        // replay protection is off -- and that trust chain resolution can be driven repeatedly with one and the
        // same request object.
        $this->arrangeFederation();
        $this->federationCache = null;

        $result = $this->check();

        $this->assertSame($this->registrationClientMock, $result?->getValue());
        $warning = $this->logContaining('warning', 'replay check');
        $this->assertStringContainsString(ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER, $warning['message']);
    }


    public function testRefusesAClientEntityIdentifierThatIsNotAnHttpUri(): void
    {
        // The issuer becomes the client identifier and is fed to trust chain resolution, so it has to be a URI.
        $this->arrangeFederation();
        $this->requestObjectIssuer = 'not-a-uri';

        $this->assertClientIsRefused();
    }


    public function testRefusesWhenTrustChainResolutionExceedsItsBudget(): void
    {
        $this->arrangeFederation();
        $this->trustChainResolutionFailure = new TrustChainResolutionBudgetException('Fetch budget exhausted.');

        $this->assertClientIsRefused();

        // Reported separately from a generic resolution failure: this is either a federation that needs higher
        // limits or someone pointing a deliberately expensive entity graph at an unauthenticated endpoint, and
        // the client identifier is what makes the latter traceable.
        $log = $this->logContaining('error', 'exceeded its budget');
        $this->assertSame(self::CLIENT_ID, $log['context']['client_id']);
    }


    public function testRefusesWhenTrustChainResolutionFails(): void
    {
        $this->arrangeFederation();
        $this->trustChainResolutionFailure = new RuntimeException('The trust anchor could not be reached.');

        $this->assertClientIsRefused();

        $this->logContaining('error', 'Error while trying to resolve trust chain');
    }


    public function testRefusesWhenTheModuleConfigurationIsInvalid(): void
    {
        $this->arrangeFederation();
        $this->trustChainResolutionFailure = new ConfigurationError('No trust anchors configured.');

        $this->assertClientIsRefused();

        $this->logContaining('error', 'Invalid OIDC configuration');
    }


    public function testVerifiesTheTrustAnchorAgainstLocallyConfiguredJwksWhenOneIsAvailable(): void
    {
        // A locally pinned trust anchor key set is the strongest link in the chain, so when the operator has
        // configured one it has to actually be used rather than merely read.
        $this->arrangeFederation();
        $this->localTrustAnchorJwksJson = json_encode(self::FEDERATION_JWKS, JSON_THROW_ON_ERROR);

        $result = $this->check();

        $this->assertSame($this->registrationClientMock, $result?->getValue());
        $this->assertSame(self::FEDERATION_JWKS, $this->trustAnchorVerifiedWithJwks);
    }


    public function testDoesNotVerifyTheTrustAnchorLocallyWhenNoJwksIsConfigured(): void
    {
        $this->arrangeFederation();
        $this->localTrustAnchorJwksJson = null;

        $this->check();

        $this->assertNull($this->trustAnchorVerifiedWithJwks);
    }


    public function testRefusesWhenTheLocallyConfiguredTrustAnchorJwksIsNotAnArray(): void
    {
        $this->arrangeFederation();
        $this->localTrustAnchorJwksJson = '"this is valid JSON but not a key set"';

        $this->assertClientIsRefused();

        $this->logContaining('error', 'Unexpected JWKS format');
    }


    public function testRefusesWhenRelyingPartyMetadataResolutionFails(): void
    {
        $this->arrangeFederation();
        $this->metadataResolutionFailure = new RuntimeException('Metadata policy could not be applied.');

        $this->assertClientIsRefused();
    }


    public function testRefusesWhenThereIsNoRelyingPartyMetadata(): void
    {
        // An entity that resolves but publishes no relying party metadata is not an RP.
        $this->arrangeFederation();
        $this->resolvedClientMetadata = null;

        $this->assertClientIsRefused();
    }


    public function testRefusesADisabledExistingClient(): void
    {
        $this->arrangeFederation();
        $this->existingClient = $this->existingClient(enabled: false);

        $this->assertClientIsRefused();
    }


    public function testRefusesToOverwriteAClientThatWasNotRegisteredThroughFederation(): void
    {
        // Otherwise anyone able to publish an entity configuration under a manually registered client's
        // identifier could replace that client's metadata -- its redirect URIs above all -- through the
        // federation path.
        $this->arrangeFederation();
        $this->existingClient = $this->existingClient(registrationType: RegistrationTypeEnum::Manual);

        $this->assertClientIsRefused();

        $this->logContaining('error', 'Unexpected existing client registration type');
    }


    public function testRefusesWhenTheClientJwksCannotBeResolved(): void
    {
        // Without the client's keys the request object signature cannot be checked, so the registration is
        // unverified and must not proceed.
        $this->arrangeFederation();
        $this->clientJwks = null;

        $this->assertClientIsRefused();
    }


    public function testRefusesARequestObjectWhoseSignatureDoesNotVerify(): void
    {
        $this->arrangeFederation();
        $this->requestObjectSignatureFailure = new JwsException('Signature verification failed.');

        $this->assertClientIsRefused();

        $this->logContaining('error', 'signature verification failed');
    }


    public function testRefusesWhenTheTrustMarkParticipationCheckFails(): void
    {
        $this->arrangeFederation();
        $this->participationLimitedByTrustMarks = true;
        $this->trustMarkValidationFailure = new RuntimeException('Required trust mark is missing.');

        $this->assertClientIsRefused();

        $this->assertTrue($this->trustMarksValidated);
    }


    public function testSkipsTrustMarkValidationWhenParticipationIsNotLimited(): void
    {
        $this->arrangeFederation();
        $this->participationLimitedByTrustMarks = false;

        $this->check();

        $this->assertFalse($this->trustMarksValidated);
    }


    public function testOnlyLogsWhenTheResolvedLeafIssuerDiffersFromTheRequestObjectIssuer(): void
    {
        // Current behaviour, pinned here rather than endorsed. The mismatch is logged and resolution carries
        // on, so the client is registered under the request object's issuer using metadata that was resolved
        // for a different entity. Reaching this state needs the trust chain resolver to return a chain for an
        // entity other than the one it was asked about.
        $this->arrangeFederation();
        $this->leafIssuer = 'https://someone-else.example.org';

        $result = $this->check();

        $this->assertSame($this->registrationClientMock, $result?->getValue());
        $this->logContaining('error', 'Client entity ID mismatch');
    }

    // Registering the client that came out of the federation.

    public function testRegistersANewClientResolvedFromFederation(): void
    {
        $this->arrangeFederation();
        $this->existingClient = null;

        $result = $this->check();

        $this->assertSame($this->registrationClientMock, $result?->getValue());
        $this->assertSame(ClientRule::class, $result?->getKey());

        $this->assertSame([$this->registrationClientMock], $this->addedClients);
        $this->assertSame([], $this->updatedClients);

        $this->assertSame(self::CLIENT_METADATA, $this->registrationArguments[0]);
        $this->assertSame(RegistrationTypeEnum::FederatedAutomatic, $this->registrationArguments[1]);
        $this->assertInstanceOf(DateTimeImmutable::class, $this->registrationArguments[2]);
        // The registration expires when the trust chain does, not on some clock of its own.
        $this->assertSame(self::TRUST_CHAIN_EXPIRATION, $this->registrationArguments[2]->getTimestamp());
        $this->assertNull($this->registrationArguments[3]);
        $this->assertSame(self::CLIENT_ID, $this->registrationArguments[4]);
        $this->assertSame(self::FEDERATION_JWKS, $this->registrationArguments[5]);
    }


    public function testUpdatesAnExistingAutomaticallyRegisteredClient(): void
    {
        $this->arrangeFederation();
        $this->existingClient = $this->existingClient();

        $result = $this->check();

        $this->assertSame($this->registrationClientMock, $result?->getValue());
        $this->assertSame([$this->registrationClientMock], $this->updatedClients);
        $this->assertSame([], $this->addedClients);
        // The existing record is handed to the factory so the update builds on it instead of replacing it.
        $this->assertSame($this->existingClient, $this->registrationArguments[3]);
    }


    public function testMarksTheRequestObjectAsUsedSoItCannotBeReplayed(): void
    {
        $this->arrangeFederation();

        $this->check();

        $this->assertCount(1, $this->cacheWrites);
        $this->assertSame(self::REQUEST_OBJECT_JTI, $this->cacheWrites[0]['value']);
        $this->assertSame(
            [self::CACHE_KEY_REQUEST_OBJECT_JTI, self::REQUEST_OBJECT_JTI],
            $this->cacheWrites[0]['key'],
        );
        // Remembering it for longer than the request object lives would only grow the cache.
        $this->assertIsInt($this->cacheWrites[0]['ttl']);
    }


    public function testStillReturnsTheClientWhenMarkingTheRequestObjectAsUsedFails(): void
    {
        // A cache write failure is an operational problem, not a reason to reject a client whose trust chain
        // and request object signature have both already been verified.
        $this->arrangeFederation();
        $this->cacheWriteFailure = new RuntimeException('The cache backend is unavailable.');

        $result = $this->check();

        $this->assertSame($this->registrationClientMock, $result?->getValue());
        $this->logContaining('error', 'mark request object as used');
    }


    public function testPassesTheResolvedRequestObjectPayloadOnToTheRequestObjectRule(): void
    {
        // The request object has already been fetched, parsed and signature-checked here, so RequestObjectRule
        // is given the result instead of repeating all of that.
        $this->arrangeFederation();

        $this->check();

        $this->assertSame(self::REQUEST_OBJECT_PAYLOAD, $this->resultBag->get(RequestObjectRule::class)?->getValue());
    }

    // Helpers.

    private function arrangeFederation(): void
    {
        $this->clientIdParam = self::CLIENT_ID;
        $this->storedClient = null;
        $this->federationEnabled = true;
    }


    private function existingClient(
        bool $enabled = true,
        RegistrationTypeEnum $registrationType = RegistrationTypeEnum::FederatedAutomatic,
    ): ClientEntityInterface&MockObject {
        $client = $this->createMock(ClientEntityInterface::class);
        $client->method('isEnabled')->willReturn($enabled);
        $client->method('getRegistrationType')->willReturn($registrationType);

        return $client;
    }


    private function sut(): ClientRule
    {
        return new ClientRule(
            $this->requestParamsResolverMock,
            new Helpers(),
            $this->clientRepositoryMock,
            $this->moduleConfigMock,
            $this->clientEntityFactoryMock,
            $this->federationMock,
            $this->jwksResolverMock,
            $this->participationValidatorMock,
            $this->loggerServiceMock,
            $this->federationCache,
        );
    }


    private function check(): ?Result
    {
        return $this->sut()->checkRule(
            $this->requestMock,
            $this->resultBag,
            $this->loggerServiceMock,
            [],
            $this->responseModeMock,
        );
    }


    private function assertClientIsRefused(): void
    {
        try {
            $this->check();
            $this->fail('The client must not have been resolved.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_client', $exception->getErrorType());
        }

        // A refusal that still wrote to the client table would be worse than no refusal at all.
        $this->assertSame([], $this->addedClients, 'No client registration may be persisted on refusal.');
        $this->assertSame([], $this->updatedClients, 'No client registration may be updated on refusal.');
    }


    /**
     * @return array{level:string,message:string,context:array}
     */
    private function logContaining(string $level, string $needle): array
    {
        foreach ($this->logs as $log) {
            if ($log['level'] === $level && str_contains($log['message'], $needle)) {
                return $log;
            }
        }

        $this->fail(sprintf(
            'Expected a "%s" log containing "%s". Logged: %s',
            $level,
            $needle,
            implode(' | ', array_column($this->logs, 'message')),
        ));
    }
}
