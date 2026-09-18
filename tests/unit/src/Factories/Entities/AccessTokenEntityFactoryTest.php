<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories\Entities;

use DateTimeImmutable;
use DateTimeZone;
use JsonException;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionParameter;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ScopeEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;

/**
 * `AccessTokenEntityFactory` has two jobs. `fromData()` hands its arguments to the `AccessTokenEntity`
 * constructor together with the factory's own `Jws` and `ModuleConfig`, which the entity needs when it
 * renders itself as a JWT. `fromState()` rebuilds an entity from a database row -- or from the protocol
 * cache's copy of one, which is whatever `getState()` produced -- by checking the column types, decoding
 * the JSON columns and turning empty optional columns into `null` before calling `fromData()`.
 *
 * The hazard in `fromData()` is positional. `boundClientId`, `boundRedirectUri` and `issuerState` share
 * the type `?string`, so a slip in the order between the factory and the entity constructor moves one
 * value into another's slot with no type error anywhere. `IssueAccessTokenTrait` calls it with a mix of
 * positional and named arguments and `AccessTokenRepository` positionally, so the parameter order and the
 * parameter names are both contract. Every string field in the fixture therefore has its own distinct
 * value, so that a swap cannot pass.
 */
#[CoversClass(AccessTokenEntityFactory::class)]
#[UsesClass(AccessTokenEntity::class)]
#[UsesClass(Helpers::class)]
#[UsesClass(ScopeEntity::class)]
#[UsesClass(ScopeEntityFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class AccessTokenEntityFactoryTest extends TestCase
{
    protected const string ID = 'access-token-id';

    protected const string CLIENT_ID = 'client-id';

    protected const string USER_ID = 'user-id';

    protected const string AUTH_CODE_ID = 'auth-code-id';

    protected const string BOUND_CLIENT_ID = 'bound-client-id';

    protected const string BOUND_REDIRECT_URI = 'https://wallet.example.org/bound';

    protected const string ISSUER_STATE = 'issuer-state-value';

    protected const string SUBJECT = 'resolved-subject';

    protected const array USER_CLAIMS = ['voperson_id' => 'v1@example.org'];

    protected const string EXPIRES_AT = '2026-01-01 12:00:00';

    /**
     * `self::EXPIRES_AT` read as UTC. A row read in server time under a timezone with an offset would give
     * a different timestamp.
     */
    protected const int EXPIRES_AT_TIMESTAMP = 1767268800;

    protected const array SCOPES = ['openid', 'profile'];

    protected const array REQUESTED_CLAIMS = ['userinfo' => ['email' => null]];

    protected const array AUTHORIZATION_DETAILS = [
        ['type' => 'openid_credential', 'credential_configuration_id' => 'cfg-id'],
    ];


    protected MockObject $clientMock;

    protected MockObject $jwsMock;

    protected MockObject $moduleConfigMock;

    protected Helpers $helpers;

    protected ScopeEntityFactory $scopeEntityFactory;


    protected function setUp(): void
    {
        $this->clientMock = $this->createMock(ClientEntityInterface::class);
        $this->clientMock->method('getIdentifier')->willReturn(self::CLIENT_ID);

        $this->jwsMock = $this->createMock(Jws::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);

        $this->helpers = new Helpers();
        $this->scopeEntityFactory = new ScopeEntityFactory();
    }


    protected function sut(?ScopeEntityFactory $scopeEntityFactory = null): AccessTokenEntityFactory
    {
        return new AccessTokenEntityFactory(
            $this->helpers,
            $scopeEntityFactory ?? $this->scopeEntityFactory,
            $this->jwsMock,
            $this->moduleConfigMock,
        );
    }


    /**
     * One value for every `fromData()` parameter, keyed by parameter name and none of them the default, so
     * that a parameter the factory silently drops shows up as a getter returning the default instead.
     *
     * @return array<string, mixed>
     */
    protected function fromDataArguments(): array
    {
        return [
            'id' => self::ID,
            'clientEntity' => $this->clientMock,
            'scopes' => array_map(
                fn(string $identifier): ScopeEntity => new ScopeEntity($identifier),
                self::SCOPES,
            ),
            'expiryDateTime' => new DateTimeImmutable(self::EXPIRES_AT, new DateTimeZone('UTC')),
            'userIdentifier' => self::USER_ID,
            'authCodeId' => self::AUTH_CODE_ID,
            'requestedClaims' => self::REQUESTED_CLAIMS,
            'isRevoked' => true,
            'flowTypeEnum' => FlowTypeEnum::VciAuthorizationCode,
            'authorizationDetails' => self::AUTHORIZATION_DETAILS,
            'boundClientId' => self::BOUND_CLIENT_ID,
            'boundRedirectUri' => self::BOUND_REDIRECT_URI,
            'issuerState' => self::ISSUER_STATE,
            'subject' => self::SUBJECT,
            'userClaims' => self::USER_CLAIMS,
        ];
    }


    /**
     * The same fixture as a database row, every column rendered as a string, plus the `client` entry which
     * the repository adds after looking the client up by `client_id`.
     *
     * @return array<string, mixed>
     */
    protected function row(array $overrides = []): array
    {
        return array_merge(
            [
                'id' => self::ID,
                'scopes' => '["openid","profile"]',
                'expires_at' => self::EXPIRES_AT,
                'user_id' => self::USER_ID,
                'client_id' => self::CLIENT_ID,
                'is_revoked' => '1',
                'auth_code_id' => self::AUTH_CODE_ID,
                'requested_claims' => '{"userinfo":{"email":null}}',
                'flow_type' => 'vci_authorization_code',
                'authorization_details' =>
                    '[{"type":"openid_credential","credential_configuration_id":"cfg-id"}]',
                'bound_client_id' => self::BOUND_CLIENT_ID,
                'bound_redirect_uri' => self::BOUND_REDIRECT_URI,
                'issuer_state' => self::ISSUER_STATE,
                'client' => $this->clientMock,
            ],
            $overrides,
        );
    }


    /**
     * @return string[]
     */
    protected function scopeIdentifiersOf(AccessTokenEntity $entity): array
    {
        return array_map(
            fn(ScopeEntity $scope): string => $scope->getIdentifier(),
            $entity->getScopes(),
        );
    }


    /**
     * Both fixtures describe the same token, so the same assertions apply whichever way it was built.
     */
    protected function assertEntityCarriesTheFixture(AccessTokenEntity $entity): void
    {
        $this->assertSame(self::ID, $entity->getIdentifier());
        $this->assertSame($this->clientMock, $entity->getClient());
        $this->assertSame(self::SCOPES, $this->scopeIdentifiersOf($entity));
        $this->assertSame(self::EXPIRES_AT_TIMESTAMP, $entity->getExpiryDateTime()->getTimestamp());
        $this->assertSame(self::USER_ID, $entity->getUserIdentifier());
        $this->assertSame(self::AUTH_CODE_ID, $entity->getAuthCodeId());
        $this->assertSame(self::REQUESTED_CLAIMS, $entity->getRequestedClaims());
        $this->assertTrue($entity->isRevoked());
        $this->assertSame(FlowTypeEnum::VciAuthorizationCode, $entity->getFlowTypeEnum());
        $this->assertSame(self::AUTHORIZATION_DETAILS, $entity->getAuthorizationDetails());
        $this->assertSame(self::BOUND_CLIENT_ID, $entity->getBoundClientId());
        $this->assertSame(self::BOUND_REDIRECT_URI, $entity->getBoundRedirectUri());
        $this->assertSame(self::ISSUER_STATE, $entity->getIssuerState());
    }


    /**
     * `OidcServerException::serverError()` appends the detail it is given to a fixed League preamble in
     * the message and leaves the hint empty, so the end of the message is what tells the three guards in
     * `fromState()` apart.
     */
    protected function assertServerError(string $detail, callable $call): void
    {
        try {
            $call();
        } catch (OidcServerException $exception) {
            $this->assertSame('server_error', $exception->getErrorType());
            $this->assertStringEndsWith(': ' . $detail, $exception->getMessage());

            return;
        }

        $this->fail(sprintf('Expected a server error ending with "%s".', $detail));
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(AccessTokenEntityFactory::class, $this->sut());
    }


    public function testFromDataPassesEveryArgumentToItsSlot(): void
    {
        $entity = $this->sut()->fromData(...$this->fromDataArguments());

        $this->assertEntityCarriesTheFixture($entity);
        // Resolved at minting and not persisted, so only a fromData() entity carries them.
        $this->assertSame(self::SUBJECT, $entity->getSubject());
        $this->assertSame(self::USER_CLAIMS, $entity->getUserClaims());
    }


    /**
     * The fixture is spread by name, so this is what makes it a claim about the whole signature: the keys
     * must be the parameter names in declaration order, and no optional parameter may be exercised with
     * its default. A parameter added to `fromData()` without a fixture value fails here, and an optional
     * whose fixture value drifted to the default would let a dropped argument pass unnoticed.
     */
    public function testFromDataFixtureExercisesEveryParameterWithANonDefaultValue(): void
    {
        $arguments = $this->fromDataArguments();
        $parameters = (new ReflectionMethod(AccessTokenEntityFactory::class, 'fromData'))->getParameters();

        $this->assertSame(
            array_map(fn(ReflectionParameter $parameter): string => $parameter->getName(), $parameters),
            array_keys($arguments),
        );

        foreach ($parameters as $parameter) {
            if (!$parameter->isDefaultValueAvailable()) {
                continue;
            }

            $this->assertNotSame(
                $parameter->getDefaultValue(),
                $arguments[$parameter->getName()],
                sprintf('The fixture value for "%s" must differ from the default.', $parameter->getName()),
            );
        }
    }


    public function testFromDataDefaultsEveryOptionalArgument(): void
    {
        $arguments = $this->fromDataArguments();

        $entity = $this->sut()->fromData(
            $arguments['id'],
            $arguments['clientEntity'],
            $arguments['scopes'],
            $arguments['expiryDateTime'],
        );

        $this->assertNull($entity->getUserIdentifier());
        $this->assertNull($entity->getAuthCodeId());
        $this->assertSame([], $entity->getRequestedClaims());
        $this->assertFalse($entity->isRevoked());
        $this->assertNull($entity->getFlowTypeEnum());
        $this->assertNull($entity->getAuthorizationDetails());
        $this->assertNull($entity->getBoundClientId());
        $this->assertNull($entity->getBoundRedirectUri());
        $this->assertNull($entity->getIssuerState());
        $this->assertNull($entity->getSubject());
        $this->assertSame([], $entity->getUserClaims());
    }


    /**
     * The factory declares `int|string|null` for the user identifier, which is what lets an integer
     * identifier reach the entity, where it is stored as a string.
     */
    public function testFromDataAcceptsAnIntegerUserIdentifier(): void
    {
        $arguments = array_merge($this->fromDataArguments(), ['userIdentifier' => 42]);

        $entity = $this->sut()->fromData(...$arguments);

        $this->assertSame('42', $entity->getUserIdentifier());
    }


    /**
     * The entity renders itself as a JWT through the `Jws` and `ModuleConfig` it was constructed with, and
     * only the factory is in a position to supply them. Expecting the calls on the factory's own mocks is
     * what proves it handed over these instances rather than some other pair.
     */
    public function testFromDataHandsTheFactoryJwsAndModuleConfigToTheEntity(): void
    {
        $signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $signatureKeyPairMock->method('getSignatureAlgorithm')->willReturn(SignatureAlgorithmEnum::RS256);
        $signatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);
        $signatureKeyPairBagMock->method('getFirstOrFail')->willReturn($signatureKeyPairMock);

        $this->moduleConfigMock->expects($this->once())
            ->method('getProtocolSignatureKeyPairBag')
            ->willReturn($signatureKeyPairBagMock);
        $this->jwsMock->expects($this->once())->method('parsedJwsFactory');

        $this->sut()->fromData(...$this->fromDataArguments())->toString();
    }


    public function testFromStateBuildsEveryFieldFromARow(): void
    {
        $this->assertEntityCarriesTheFixture($this->sut()->fromState($this->row()));
    }


    /**
     * The subject and the user claims are resolved when the token is minted and travel with that entity only:
     * no column stores them, and the JWT of a stored token is never rebuilt. The endpoints which need the
     * subject later read it from the presented JWT.
     */
    public function testFromStateBuildsAnEntityWithoutASubjectOrUserClaims(): void
    {
        $entity = $this->sut()->fromState($this->row());

        $this->assertNull($entity->getSubject());
        $this->assertSame([], $entity->getUserClaims());
    }


    /**
     * `AccessTokenRepository::findById()` stores `getState()` in the protocol cache and feeds it back to
     * `fromState()` on the next hit, with only `client` added. With every field set, a `getState()` key
     * that `fromState()` does not read comes back at its default and the states differ. The cached
     * `scopes` are a JSON object keyed by identifier, which `addScope()` re-keys the same way on the
     * rebuilt entity.
     */
    public function testFromStateRebuildsTheEntityFromItsOwnState(): void
    {
        $original = $this->sut()->fromData(...$this->fromDataArguments());

        $rebuilt = $this->sut()->fromState($original->getState() + ['client' => $this->clientMock]);

        $this->assertSame($original->getState(), $rebuilt->getState());
        $this->assertSame($this->clientMock, $rebuilt->getClient());
        $this->assertEntityCarriesTheFixture($rebuilt);
    }


    /**
     * The test container runs on UTC, where reading `expires_at` in server time and reading it as UTC give
     * the same instant, so the timestamp assertion in the plain row test cannot tell them apart. This one
     * can: on Pacific/Chatham the two readings differ by the offset.
     */
    public function testFromStateReadsExpiresAtAsUtcWhateverTheServerTimezone(): void
    {
        $previous = date_default_timezone_get();
        date_default_timezone_set('Pacific/Chatham');

        try {
            $entity = $this->sut()->fromState($this->row());
        } finally {
            date_default_timezone_set($previous);
        }

        $this->assertSame(self::EXPIRES_AT_TIMESTAMP, $entity->getExpiryDateTime()->getTimestamp());
        $this->assertSame('UTC', $entity->getExpiryDateTime()->getTimezone()->getName());
    }


    public function testFromStateBuildsEachScopeThroughTheScopeEntityFactory(): void
    {
        $requested = [];
        $scopeEntityFactoryMock = $this->createMock(ScopeEntityFactory::class);
        $scopeEntityFactoryMock->method('fromData')->willReturnCallback(
            function (string $identifier) use (&$requested): ScopeEntity {
                $requested[] = $identifier;

                return new ScopeEntity($identifier);
            },
        );

        $entity = $this->sut($scopeEntityFactoryMock)->fromState($this->row());

        $this->assertSame(self::SCOPES, $requested);
        $this->assertSame(self::SCOPES, $this->scopeIdentifiersOf($entity));
    }


    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function invalidStateProvider(): array
    {
        return [
            'scopes not a string' => [['scopes' => ['openid']]],
            'scopes null' => [['scopes' => null]],
            'id not a string' => [['id' => 123]],
            'expires_at not a string' => [['expires_at' => 1767268800]],
            'client missing, as for an unknown client_id' => [['client' => null]],
            'client is a string' => [['client' => 'client-id']],
        ];
    }


    #[DataProvider('invalidStateProvider')]
    public function testFromStateRejectsAnInvalidField(array $overrides): void
    {
        $this->assertServerError(
            'Invalid Access Token Entity state',
            fn() => $this->sut()->fromState($this->row($overrides)),
        );
    }


    /**
     * The guard asks for the module's `ClientEntityInterface`, not the League one that `fromData()`
     * accepts, so an object satisfying only the latter is refused the same way as no client at all.
     */
    public function testFromStateRejectsAClientWhichIsOnlyALeagueClient(): void
    {
        $this->assertServerError(
            'Invalid Access Token Entity state',
            fn() => $this->sut()->fromState(
                $this->row(['client' => $this->createMock(OAuth2ClientEntityInterface::class)]),
            ),
        );
    }


    /**
     * @return array<string, array{string}>
     */
    public static function scopesNotDecodingToAnArrayProvider(): array
    {
        return [
            'a JSON string' => ['"openid"'],
            'a JSON number' => ['5'],
            'JSON null' => ['null'],
        ];
    }


    #[DataProvider('scopesNotDecodingToAnArrayProvider')]
    public function testFromStateRejectsScopesWhichDoNotDecodeToAnArray(string $scopes): void
    {
        $this->assertServerError(
            'Invalid Access Token Entity state: scopes',
            fn() => $this->sut()->fromState($this->row(['scopes' => $scopes])),
        );
    }


    /**
     * @return array<string, array{string}>
     */
    public static function invalidJsonProvider(): array
    {
        return [
            'empty string' => [''],
            'truncated' => ['["openid"'],
            'not JSON at all' => ['openid profile'],
        ];
    }


    #[DataProvider('invalidJsonProvider')]
    public function testFromStateLetsUnparsableScopesThrow(string $scopes): void
    {
        $this->expectException(JsonException::class);

        $this->sut()->fromState($this->row(['scopes' => $scopes]));
    }


    /**
     * @return array<string, array{string, string}>
     */
    public static function optionalStringColumnProvider(): array
    {
        return [
            'user_id' => ['user_id', 'getUserIdentifier'],
            'auth_code_id' => ['auth_code_id', 'getAuthCodeId'],
            'bound_client_id' => ['bound_client_id', 'getBoundClientId'],
            'bound_redirect_uri' => ['bound_redirect_uri', 'getBoundRedirectUri'],
            'issuer_state' => ['issuer_state', 'getIssuerState'],
        ];
    }


    /**
     * @return array<string, array{string, string, mixed}>
     */
    public static function emptyOptionalStringColumnProvider(): array
    {
        $rows = [];

        foreach (self::optionalStringColumnProvider() as $label => [$column, $getter]) {
            $rows[$label . ' is NULL'] = [$column, $getter, null];
            $rows[$label . ' is empty'] = [$column, $getter, ''];
            $rows[$label . ' is the string 0'] = [$column, $getter, '0'];
        }

        return $rows;
    }


    /**
     * The optional columns are normalised with `empty()`, so the string `'0'` is dropped along with `NULL`
     * and the empty string. A user whose identifier is literally `0` would lose it. Current behaviour,
     * pinned so that changing it is a deliberate act.
     */
    #[DataProvider('emptyOptionalStringColumnProvider')]
    public function testFromStateTurnsAnEmptyOptionalColumnIntoNull(
        string $column,
        string $getter,
        mixed $value,
    ): void {
        $entity = $this->sut()->fromState($this->row([$column => $value]));

        $this->assertNull($entity->$getter());
    }


    /**
     * The cast to string is load-bearing for every column but `user_id`: `fromData()` types the others as
     * `?string`, so an integer in the row would otherwise be a `TypeError`.
     */
    #[DataProvider('optionalStringColumnProvider')]
    public function testFromStateCastsANonEmptyOptionalColumnToString(string $column, string $getter): void
    {
        $entity = $this->sut()->fromState($this->row([$column => 123]));

        $this->assertSame('123', $entity->$getter());
    }


    /**
     * @return array<string, array{mixed, bool}>
     */
    public static function isRevokedProvider(): array
    {
        return [
            'string 0' => ['0', false],
            'string 1' => ['1', true],
            'int 0' => [0, false],
            'int 1' => [1, true],
            'false' => [false, false],
            'true' => [true, true],
        ];
    }


    /**
     * `is_revoked` is a BOOLEAN column. Which PHP type it comes back as depends on the driver, and the
     * protocol cache hands back the `bool` from `getState()`, so every rendering a `(bool)` cast can take
     * is pinned.
     */
    #[DataProvider('isRevokedProvider')]
    public function testFromStateReadsIsRevokedAsTheDriversRenderIt(mixed $value, bool $expected): void
    {
        $entity = $this->sut()->fromState($this->row(['is_revoked' => $value]));

        $this->assertSame($expected, $entity->isRevoked());
    }


    /**
     * @return array<string, array{mixed, ?\SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum}>
     */
    public static function flowTypeProvider(): array
    {
        $rows = [
            'NULL' => [null, null],
            'empty' => ['', null],
            'unknown value' => ['not-a-flow', null],
        ];

        foreach (FlowTypeEnum::cases() as $case) {
            $rows[$case->name] = [$case->value, $case];
        }

        return $rows;
    }


    /**
     * A value which is no longer a `FlowTypeEnum` case maps to `null` rather than failing, so a token
     * whose stored flow type is unrecognised loses its flow type silently. Pinned as current behaviour.
     */
    #[DataProvider('flowTypeProvider')]
    public function testFromStateMapsFlowType(mixed $value, ?FlowTypeEnum $expected): void
    {
        $entity = $this->sut()->fromState($this->row(['flow_type' => $value]));

        $this->assertSame($expected, $entity->getFlowTypeEnum());
    }


    /**
     * @return array<string, array{mixed, array}>
     */
    public static function requestedClaimsProvider(): array
    {
        return [
            'NULL' => [null, []],
            'empty' => ['', []],
            'empty list' => ['[]', []],
            'empty object' => ['{}', []],
            'claims' => ['{"userinfo":{"email":null}}', ['userinfo' => ['email' => null]]],
        ];
    }


    #[DataProvider('requestedClaimsProvider')]
    public function testFromStateDecodesRequestedClaims(mixed $value, array $expected): void
    {
        $entity = $this->sut()->fromState($this->row(['requested_claims' => $value]));

        $this->assertSame($expected, $entity->getRequestedClaims());
    }


    #[DataProvider('scopesNotDecodingToAnArrayProvider')]
    public function testFromStateRejectsRequestedClaimsWhichDoNotDecodeToAnArray(string $value): void
    {
        $this->assertServerError(
            'Invalid Access Token Entity state: requested claims',
            fn() => $this->sut()->fromState($this->row(['requested_claims' => $value])),
        );
    }


    public function testFromStateLetsUnparsableRequestedClaimsThrow(): void
    {
        $this->expectException(JsonException::class);

        $this->sut()->fromState($this->row(['requested_claims' => '{"userinfo":']));
    }


    /**
     * @return array<string, array{mixed, ?array}>
     */
    public static function authorizationDetailsProvider(): array
    {
        return [
            'NULL' => [null, null],
            'empty list stays a list' => ['[]', []],
            'details' => [
                '[{"type":"openid_credential","credential_configuration_id":"cfg-id"}]',
                [['type' => 'openid_credential', 'credential_configuration_id' => 'cfg-id']],
            ],
            'a JSON string' => ['"openid_credential"', null],
            'a JSON number' => ['5', null],
            'JSON null' => ['null', null],
            'not a string, so not decoded' => [[['type' => 'openid_credential']], null],
        ];
    }


    /**
     * `authorization_details` is the lenient column: only a string is decoded, and only an array result is
     * kept -- a non-string, or a string decoding to anything else, becomes `null` without complaint, while
     * a string which is not JSON still throws. An empty list is an array, so it survives as `[]` rather
     * than collapsing to `null`.
     */
    #[DataProvider('authorizationDetailsProvider')]
    public function testFromStateDecodesAuthorizationDetails(mixed $value, ?array $expected): void
    {
        $entity = $this->sut()->fromState($this->row(['authorization_details' => $value]));

        $this->assertSame($expected, $entity->getAuthorizationDetails());
    }


    /**
     * @return array<string, array{string, string, mixed}>
     */
    public static function missingOptionalColumnProvider(): array
    {
        return [
            'user_id' => ['user_id', 'getUserIdentifier', null],
            'auth_code_id' => ['auth_code_id', 'getAuthCodeId', null],
            'requested_claims' => ['requested_claims', 'getRequestedClaims', []],
            'flow_type' => ['flow_type', 'getFlowTypeEnum', null],
            'authorization_details' => ['authorization_details', 'getAuthorizationDetails', null],
            'bound_client_id' => ['bound_client_id', 'getBoundClientId', null],
            'bound_redirect_uri' => ['bound_redirect_uri', 'getBoundRedirectUri', null],
            'issuer_state' => ['issuer_state', 'getIssuerState', null],
        ];
    }


    /**
     * `authorization_details` is read with `isset()` and the other optional columns with `empty()`, and
     * neither minds a key which is not there, so a cached state written before one of these columns
     * existed still builds, with the column at its default. The required columns and `is_revoked` are read
     * directly and are not part of this.
     */
    #[DataProvider('missingOptionalColumnProvider')]
    public function testFromStateTreatsAMissingOptionalColumnAsItsDefault(
        string $column,
        string $getter,
        mixed $expected,
    ): void {
        $row = $this->row();
        unset($row[$column]);

        $this->assertSame($expected, $this->sut()->fromState($row)->$getter());
    }


    public function testFromStateLetsUnparsableAuthorizationDetailsThrow(): void
    {
        $this->expectException(JsonException::class);

        $this->sut()->fromState($this->row(['authorization_details' => '[{"type":']));
    }
}
