<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PreAuthorizedCodeClientRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Stringable;

/**
 * The client half of a token request redeeming a pre-authorized code, where client authentication is optional.
 *
 * The rule has four answers, and each has its test: nobody (an anonymous request gives no result), a
 * self-declared identifier (a `client_id` naming no registered client is taken at its word), an authenticated
 * client (credentials, or a `client_id` naming a registered client, go through the resolver and the result is
 * that client's identifier) and a refusal (credentials the resolver cannot verify, a registered client the
 * resolver will not accept as presented, or a `client_id` which contradicts the credentials, each `invalid_client`).
 * What separates the second from the third is a registry lookup by the identifier presented, and what keeps a
 * disabled or expired registration from being taken on trust is that only an active one is handed to the
 * resolver as pre-fetched.
 */
#[CoversClass(PreAuthorizedCodeClientRule::class)]
#[UsesClass(Result::class)]
#[UsesClass(ResultBag::class)]
#[AllowMockObjectsWithoutExpectations]
class PreAuthorizedCodeClientRuleTest extends TestCase
{
    private const string CLIENT_ID = 'https://wallet.example.org';

    private const string OTHER_CLIENT_ID = 'https://other-wallet.example.org';


    private RequestParamsResolver&MockObject $requestParamsResolverMock;

    private AuthenticatedOAuth2ClientResolver&MockObject $authenticatedOAuth2ClientResolverMock;

    private ClientRepository&MockObject $clientRepositoryMock;

    private LoggerService&MockObject $loggerServiceMock;

    private ServerRequestInterface&MockObject $requestMock;

    private ClientEntityInterface&MockObject $clientMock;

    /** @var array<int, array{level: string, message: string, context: array}> */
    private array $logRecords = [];


    protected function setUp(): void
    {
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->authenticatedOAuth2ClientResolverMock = $this->createMock(AuthenticatedOAuth2ClientResolver::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->clientMock = $this->createMock(ClientEntityInterface::class);
        $this->clientMock->method('getIdentifier')->willReturn(self::CLIENT_ID);

        foreach (['debug', 'warning'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string|Stringable $message, array $context = []) use ($level): void {
                    $this->logRecords[] = [
                        'level' => $level,
                        'message' => (string)$message,
                        'context' => $context,
                    ];
                },
            );
        }
    }


    private function sut(): PreAuthorizedCodeClientRule
    {
        return new PreAuthorizedCodeClientRule(
            $this->requestParamsResolverMock,
            new Helpers(),
            $this->authenticatedOAuth2ClientResolverMock,
            $this->clientRepositoryMock,
        );
    }


    /**
     * The only parameter the rule reads is `client_id`, over the methods the caller allows.
     */
    public function testAnonymousRequestIdentifiesNobodyAndAsksNothingOfTheResolverOrTheRegistry(): void
    {
        $this->requestParamsResolverMock->expects($this->once())->method('getAsStringBasedOnAllowedMethods')
            ->with(ParamsEnum::ClientId->value, $this->identicalTo($this->requestMock), [HttpMethodsEnum::POST])
            ->willReturn(null);
        $this->requestParamsResolverMock->expects($this->never())
            ->method($this->logicalNot($this->equalTo('getAsStringBasedOnAllowedMethods')));
        $this->authenticatedOAuth2ClientResolverMock->method('presentsClientCredentials')->willReturn(false);
        $this->authenticatedOAuth2ClientResolverMock->expects($this->never())->method('forAnySupportedMethod');
        $this->clientRepositoryMock->expects($this->never())->method('findById');

        $this->assertNull($this->check());
        $this->assertLogged('debug', 'PreAuthorizedCodeClientRule: anonymous access, no client identified.');
    }


    /**
     * An empty `client_id` is no identifier.
     */
    public function testAnEmptyClientIdIsAnonymous(): void
    {
        $this->withClientId('');
        $this->authenticatedOAuth2ClientResolverMock->method('presentsClientCredentials')->willReturn(false);
        $this->authenticatedOAuth2ClientResolverMock->expects($this->never())->method('forAnySupportedMethod');
        $this->clientRepositoryMock->expects($this->never())->method('findById');

        $this->assertNull($this->check());
    }


    public function testAClientIdNamingNoRegisteredClientIsTakenAsTheSelfDeclaredIdentifier(): void
    {
        $this->withClientId(self::CLIENT_ID);
        $this->authenticatedOAuth2ClientResolverMock->method('presentsClientCredentials')->willReturn(false);
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with(self::CLIENT_ID)
            ->willReturn(null);
        $this->authenticatedOAuth2ClientResolverMock->expects($this->never())->method('forAnySupportedMethod');

        $this->assertResolvedTo(self::CLIENT_ID, $this->check());
        $this->assertLogged(
            'debug',
            'PreAuthorizedCodeClientRule: non-registered client identified by `client_id` alone.',
            ['client_id' => self::CLIENT_ID],
        );
    }


    /**
     * Credentials go to the resolver with no pre-fetched client, since nothing named one, and the client
     * they authenticate is the answer.
     */
    public function testCredentialsAloneAuthenticateTheClientTheyName(): void
    {
        $this->withClientId(null);
        $this->authenticatedOAuth2ClientResolverMock->method('presentsClientCredentials')->willReturn(true);
        $this->clientRepositoryMock->expects($this->never())->method('findById');
        $this->authenticatedOAuth2ClientResolverMock->expects($this->once())->method('forAnySupportedMethod')
            ->with($this->identicalTo($this->requestMock), $this->isNull())
            ->willReturn($this->resolved(ClientAuthenticationMethodsEnum::PrivateKeyJwt));

        $this->assertResolvedTo(self::CLIENT_ID, $this->check());
        $this->assertLogged(
            'debug',
            'PreAuthorizedCodeClientRule: client resolved.',
            ['client_id' => self::CLIENT_ID, 'method' => 'private_key_jwt'],
        );
    }


    /**
     * Credentials which cannot be verified are a refusal, not anonymous access: a wallet which presents an
     * assertion this issuer has no key for is told so here, rather than issued an anonymous token whose key
     * proof is then refused at the credential endpoint for naming it.
     */
    public function testCredentialsTheResolverCannotVerifyAreRefusedAsInvalidClient(): void
    {
        $this->withClientId(null);
        $this->authenticatedOAuth2ClientResolverMock->method('presentsClientCredentials')->willReturn(true);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')->willReturn(null);

        $this->assertRefused();
        $this->assertLogged(
            'warning',
            'Token request rejected: the client could not be authenticated.',
            ['client_id' => null, 'presents_credentials' => true],
        );
    }


    /**
     * A `client_id` sent alongside credentials has to name the client they authenticate (RFC 7521, section
     * 4.2). One naming a registered client reaches the resolver as pre-fetched, and the resolver refuses the
     * mismatch itself; one naming no registered client does not, so the rule compares the two.
     */
    public function testAClientIdContradictingTheCredentialsIsRefused(): void
    {
        $this->withClientId(self::OTHER_CLIENT_ID);
        $this->authenticatedOAuth2ClientResolverMock->method('presentsClientCredentials')->willReturn(true);
        $this->clientRepositoryMock->method('findById')->with(self::OTHER_CLIENT_ID)->willReturn(null);
        $this->authenticatedOAuth2ClientResolverMock->expects($this->once())->method('forAnySupportedMethod')
            ->with($this->identicalTo($this->requestMock), $this->isNull())
            ->willReturn($this->resolved(ClientAuthenticationMethodsEnum::PrivateKeyJwt));

        $this->assertRefused();
        $this->assertLogged(
            'warning',
            'Token request rejected: `client_id` does not name the client the credentials authenticate.',
            ['client_id' => self::OTHER_CLIENT_ID, 'authenticated_client_id' => self::CLIENT_ID],
        );
    }


    /**
     * The answer is the same identifier a self-declared `client_id` would have given, so what tells the two
     * apart here is that the resolver was asked: the credentials were checked, not the identifier taken on
     * trust.
     */
    public function testAClientIdAgreeingWithTheCredentialsIsAccepted(): void
    {
        $this->withClientId(self::CLIENT_ID);
        $this->authenticatedOAuth2ClientResolverMock->method('presentsClientCredentials')->willReturn(true);
        $this->clientRepositoryMock->method('findById')->with(self::CLIENT_ID)->willReturn(null);
        $this->authenticatedOAuth2ClientResolverMock->expects($this->once())->method('forAnySupportedMethod')
            ->willReturn($this->resolved(ClientAuthenticationMethodsEnum::PrivateKeyJwt));

        $this->assertResolvedTo(self::CLIENT_ID, $this->check());
        $this->assertLogged(
            'debug',
            'PreAuthorizedCodeClientRule: client resolved.',
            ['client_id' => self::CLIENT_ID, 'method' => 'private_key_jwt'],
        );
    }


    /**
     * A `client_id` naming a registered, active client is not self-declared: it is handed to the resolver as
     * pre-fetched, which is where a public client is accepted as presented and a confidential one, or one
     * registered with another method, is not.
     */
    public function testAClientIdNamingAnActiveRegisteredClientGoesThroughTheResolver(): void
    {
        $this->withClientId(self::CLIENT_ID);
        $this->withRegisteredClient(isEnabled: true, isExpired: false);
        $this->authenticatedOAuth2ClientResolverMock->method('presentsClientCredentials')->willReturn(false);
        $this->authenticatedOAuth2ClientResolverMock->expects($this->once())->method('forAnySupportedMethod')
            ->with($this->identicalTo($this->requestMock), $this->identicalTo($this->clientMock))
            ->willReturn($this->resolved(ClientAuthenticationMethodsEnum::None));

        $this->assertResolvedTo(self::CLIENT_ID, $this->check());
    }


    /**
     * With credentials as well, the registered client still goes over as pre-fetched, which is what lets the
     * resolver cross-check the client the credentials name against the one `client_id` named.
     */
    public function testARegisteredClientPresentingCredentialsIsHandedToTheResolverWithThem(): void
    {
        $this->withClientId(self::CLIENT_ID);
        $this->withRegisteredClient(isEnabled: true, isExpired: false);
        $this->authenticatedOAuth2ClientResolverMock->method('presentsClientCredentials')->willReturn(true);
        $this->authenticatedOAuth2ClientResolverMock->expects($this->once())->method('forAnySupportedMethod')
            ->with($this->identicalTo($this->requestMock), $this->identicalTo($this->clientMock))
            ->willReturn($this->resolved(ClientAuthenticationMethodsEnum::ClientSecretBasic));

        $this->assertResolvedTo(self::CLIENT_ID, $this->check());
        $this->assertLogged(
            'debug',
            'PreAuthorizedCodeClientRule: client resolved.',
            ['client_id' => self::CLIENT_ID, 'method' => 'client_secret_basic'],
        );
    }


    public function testARegisteredClientTheResolverWillNotAcceptAsPresentedIsRefused(): void
    {
        $this->withClientId(self::CLIENT_ID);
        $this->withRegisteredClient(isEnabled: true, isExpired: false);
        $this->authenticatedOAuth2ClientResolverMock->method('presentsClientCredentials')->willReturn(false);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')->willReturn(null);

        $this->assertRefused();
        $this->assertLogged(
            'warning',
            'Token request rejected: the client could not be authenticated.',
            ['client_id' => self::CLIENT_ID, 'presents_credentials' => false],
        );
    }


    /**
     * The resolver takes a pre-fetched client on trust, so a registration which is disabled or expired is
     * still what makes the request the resolver's to refuse, but is not handed over: the resolver's own
     * lookup then refuses it as inactive, where a bare `client_id` would otherwise have been taken as
     * self-declared and the registration's disabling would have counted for nothing.
     */
    #[DataProvider('inactiveRegistrationProvider')]
    public function testAnInactiveRegistrationIsNeitherSelfDeclaredNorHandedToTheResolver(
        bool $isEnabled,
        bool $isExpired,
        bool $presentsCredentials,
    ): void {
        $this->withClientId(self::CLIENT_ID);
        $this->withRegisteredClient($isEnabled, $isExpired);
        $this->authenticatedOAuth2ClientResolverMock->method('presentsClientCredentials')
            ->willReturn($presentsCredentials);
        $this->authenticatedOAuth2ClientResolverMock->expects($this->once())->method('forAnySupportedMethod')
            ->with($this->identicalTo($this->requestMock), $this->isNull())
            ->willReturn(null);

        $this->assertRefused();
        $this->assertLogged(
            'warning',
            'Token request rejected: the client could not be authenticated.',
            ['client_id' => self::CLIENT_ID, 'presents_credentials' => $presentsCredentials],
        );
    }


    public static function inactiveRegistrationProvider(): array
    {
        return [
            'disabled, client_id alone' => [false, false, false],
            'expired, client_id alone' => [true, true, false],
            'disabled, with credentials' => [false, false, true],
            'expired, with credentials' => [true, true, true],
        ];
    }


    private function withClientId(?string $clientId): void
    {
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')
            ->with(ParamsEnum::ClientId->value, $this->identicalTo($this->requestMock), [HttpMethodsEnum::POST])
            ->willReturn($clientId);
    }


    private function withRegisteredClient(bool $isEnabled, bool $isExpired): void
    {
        $this->clientMock->method('isEnabled')->willReturn($isEnabled);
        $this->clientMock->method('isExpired')->willReturn($isExpired);
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with(self::CLIENT_ID)
            ->willReturn($this->clientMock);
    }


    private function resolved(ClientAuthenticationMethodsEnum $method): ResolvedClientAuthenticationMethod
    {
        return new ResolvedClientAuthenticationMethod($this->clientMock, $method);
    }


    private function check(): ?Result
    {
        return $this->sut()->checkRule(
            $this->requestMock,
            new ResultBag(),
            $this->loggerServiceMock,
            [],
            new QueryResponseMode(),
            [HttpMethodsEnum::POST],
        );
    }


    private function assertResolvedTo(string $clientId, ?Result $result): void
    {
        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame(PreAuthorizedCodeClientRule::class, $result->getKey());
        $this->assertSame($clientId, $result->getValue());
    }


    private function assertRefused(): void
    {
        try {
            $this->check();
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_client', $exception->getErrorType());
            $this->assertSame(401, $exception->getHttpStatusCode());

            return;
        }

        $this->fail('The request was not refused.');
    }


    private function assertLogged(string $level, string $message, ?array $context = null): void
    {
        foreach ($this->logRecords as $record) {
            if ($record['level'] !== $level || $record['message'] !== $message) {
                continue;
            }

            if ($context !== null) {
                $this->assertSame($context, $record['context']);
            }

            return;
        }

        $this->fail(sprintf('No %s log record with message "%s".', $level, $message));
    }
}
