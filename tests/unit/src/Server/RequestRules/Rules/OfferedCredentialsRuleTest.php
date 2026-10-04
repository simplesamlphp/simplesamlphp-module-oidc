<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\IssuerStateEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AuthorizationDetailsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IssuerStateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\OfferedCredentialsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use Stringable;

/**
 * The rule which keeps a request following a Credential Offer to the credential configurations that offer offered.
 *
 * It runs after IssuerStateRule, ScopeRule and AuthorizationDetailsRule, and reads their results: the issuer state
 * of the offer, the scopes requested (only those which are configuration IDs are the offer's to decide), and the
 * authorization details of type openid_credential. A configuration the offer did not offer is refused back to the
 * redirect URI, with `invalid_scope` or `invalid_authorization_details` after the parameter which named it.
 */
#[CoversClass(OfferedCredentialsRule::class)]
#[AllowMockObjectsWithoutExpectations]
class OfferedCredentialsRuleTest extends TestCase
{
    protected const string ISSUER_STATE = '3b4d8f1e6a2c9075d1e8f4a6b2c3d5e7f9a1b3c5d7e9f2a4b6c8d0e2f4a6b8c0';

    protected const string REDIRECT_URI = 'https://wallet.example.org/callback';

    protected const string STATE = 'state-of-the-wallet';

    protected const string CLIENT_ID = 'wallet-client-id';

    protected const string OFFERED = 'UniversityDegreeCredential';

    protected const string NOT_OFFERED = 'ResearchAndScholarshipCredentialDcSdJwt';


    protected MockObject $issuerStateRepositoryMock;

    protected MockObject $moduleConfigMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $requestMock;

    protected MockObject $clientMock;

    /** @var array<int,array{level:string,message:string,context:array}> */
    protected array $logRecords = [];


    protected function setUp(): void
    {
        $this->issuerStateRepositoryMock = $this->createMock(IssuerStateRepository::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciCredentialConfigurationIdsSupported')
            ->willReturn([self::OFFERED, self::NOT_OFFERED]);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->clientMock = $this->createMock(ClientEntityInterface::class);
        $this->clientMock->method('getIdentifier')->willReturn(self::CLIENT_ID);

        $this->logRecords = [];
        foreach (['debug', 'info', 'notice', 'warning', 'error'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string|Stringable $message, array $context = []) use ($level): void {
                    $this->logRecords[] = ['level' => $level, 'message' => (string)$message, 'context' => $context];
                },
            );
        }
    }


    protected function sut(): OfferedCredentialsRule
    {
        return new OfferedCredentialsRule(
            $this->createStub(RequestParamsResolver::class),
            new Helpers(),
            $this->issuerStateRepositoryMock,
            $this->moduleConfigMock,
        );
    }


    /**
     * What the rules before this one resolved: the client, its redirect URI and the state, which an error is sent
     * back with, the issuer state, the scopes and the authorization details.
     *
     * @param string[] $scopes
     * @param mixed[]|null $authorizationDetails
     */
    protected function resultBag(
        ?string $issuerState = self::ISSUER_STATE,
        array $scopes = ['openid'],
        ?array $authorizationDetails = null,
    ): ResultBag {
        $resultBag = new ResultBag();
        $resultBag->add(new Result(ClientRule::class, $this->clientMock));
        $resultBag->add(new Result(ClientRedirectUriRule::class, self::REDIRECT_URI));
        $resultBag->add(new Result(StateRule::class, self::STATE));
        $resultBag->add(new Result(IssuerStateRule::class, $issuerState));
        $resultBag->add(new Result(
            ScopeRule::class,
            array_map(fn(string $scope): ScopeEntity => new ScopeEntity($scope), $scopes),
        ));
        if ($authorizationDetails !== null) {
            $resultBag->add(new Result(AuthorizationDetailsRule::class, $authorizationDetails));
        }

        return $resultBag;
    }


    /**
     * @param string[] $credentialConfigurationIds
     */
    protected function theOfferOffered(array $credentialConfigurationIds): void
    {
        $issuerState = $this->createStub(IssuerStateEntity::class);
        $issuerState->method('getCredentialConfigurationIds')->willReturn($credentialConfigurationIds);
        $this->issuerStateRepositoryMock->method('find')->with(self::ISSUER_STATE)->willReturn($issuerState);
    }


    /**
     * @return array<string,string>
     */
    protected function authorizationDetail(mixed $credentialConfigurationId): array
    {
        return ['type' => 'openid_credential', 'credential_configuration_id' => $credentialConfigurationId];
    }


    protected function refusal(ResultBag $resultBag): OidcServerException
    {
        try {
            $this->sut()->checkRule($this->requestMock, $resultBag, $this->loggerServiceMock);
        } catch (OidcServerException $exception) {
            return $exception;
        }

        $this->fail('A credential configuration the offer did not offer must be refused.');
    }


    public function testIsKeyedByItsClassName(): void
    {
        $this->assertSame(OfferedCredentialsRule::class, $this->sut()->getKey());
    }


    /**
     * A request which follows no offer, or one IssuerStateRule ignored the issuer_state of (not an OpenID4VCI one),
     * is not this rule's to judge: nothing is looked up, and nothing refused.
     *
     * @throws \Throwable
     */
    public function testAsksNothingOfARequestWhichFollowsNoOffer(): void
    {
        $this->issuerStateRepositoryMock->expects($this->never())->method('find');

        $result = $this->sut()->checkRule(
            $this->requestMock,
            $this->resultBag(issuerState: null, scopes: [self::NOT_OFFERED]),
            $this->loggerServiceMock,
        );

        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame(OfferedCredentialsRule::class, $result->getKey());
        $this->assertNull($result->getValue());
    }


    /**
     * @return array<string,array{string[], ?array}>
     */
    public static function requestsForWhatWasOfferedProvider(): array
    {
        return [
            'the offered configuration as a scope' => [['openid', self::OFFERED], null],
            'the offered configuration as an authorization detail' => [
                ['openid'],
                [['type' => 'openid_credential', 'credential_configuration_id' => self::OFFERED]],
            ],
            'scopes which are not configurations' => [['openid', 'profile', 'offline_access'], null],
            'the offered configuration both ways' => [
                ['openid', self::OFFERED],
                [['type' => 'openid_credential', 'credential_configuration_id' => self::OFFERED]],
            ],
        ];
    }


    /**
     * @param string[] $scopes
     * @throws \Throwable
     */
    #[DataProvider('requestsForWhatWasOfferedProvider')]
    public function testAcceptsARequestForWhatTheOfferOffered(array $scopes, ?array $authorizationDetails): void
    {
        $this->theOfferOffered([self::OFFERED]);

        $result = $this->sut()->checkRule(
            $this->requestMock,
            $this->resultBag(scopes: $scopes, authorizationDetails: $authorizationDetails),
            $this->loggerServiceMock,
        );

        $this->assertInstanceOf(Result::class, $result);
        $this->assertNull($result->getValue());
    }


    /**
     * A scope which is a configuration ID asks for that credential (OpenID4VCI 1.0 section 5.1.2), so one the
     * offer did not offer is refused as the scope it is, back to the redirect URI with the state.
     *
     * @throws \Throwable
     */
    public function testRefusesAScopeForAConfigurationTheOfferDidNotOffer(): void
    {
        $this->theOfferOffered([self::OFFERED]);

        $exception = $this->refusal($this->resultBag(scopes: ['openid', self::OFFERED, self::NOT_OFFERED]));

        $this->assertSame('invalid_scope', $exception->getErrorType());
        $this->assertSame(self::REDIRECT_URI, $exception->getRedirectUri());
        $this->assertSame(self::STATE, $exception->getPayload()['state'] ?? null);
        $this->assertSame(
            [
                [
                    'level' => 'notice',
                    'message' => 'Authorization request rejected: `scope` names a credential configuration its ' .
                        'Credential Offer did not offer.',
                    'context' => ['client_id' => self::CLIENT_ID, 'scope' => self::NOT_OFFERED],
                ],
            ],
            $this->logRecords,
        );
    }


    /**
     * @return array<string,array{mixed}>
     */
    public static function authorizationDetailsNotOfferedProvider(): array
    {
        return [
            'a configuration the offer did not offer' => [self::NOT_OFFERED],
            'a configuration no issuer has' => ['unknown-configuration'],
            'a configuration ID which is not a string' => [[self::OFFERED]],
        ];
    }


    /**
     * Authorization details name the credential they ask for (OpenID4VCI 1.0 section 5.1.1), so one naming a
     * configuration the offer did not offer is refused with the RFC 9396 error for them, back to the redirect
     * URI with the state, even next to one which names the offered configuration.
     *
     * @throws \Throwable
     */
    #[DataProvider('authorizationDetailsNotOfferedProvider')]
    public function testRefusesAnAuthorizationDetailForAConfigurationTheOfferDidNotOffer(
        mixed $credentialConfigurationId,
    ): void {
        $this->theOfferOffered([self::OFFERED]);

        $exception = $this->refusal($this->resultBag(authorizationDetails: [
            $this->authorizationDetail(self::OFFERED),
            $this->authorizationDetail($credentialConfigurationId),
        ]));

        $this->assertSame('invalid_authorization_details', $exception->getErrorType());
        $this->assertSame(self::REDIRECT_URI, $exception->getRedirectUri());
        $this->assertSame(self::STATE, $exception->getPayload()['state'] ?? null);
    }


    /**
     * Each parameter is judged on its own: a configuration the offer did not offer is refused through whichever
     * parameter names it, whatever the other one asks for.
     *
     * @return array<string,array{string[], string, string}>
     */
    public static function oneParameterBeyondTheOfferProvider(): array
    {
        return [
            'an offered scope, an authorization detail beyond the offer' => [
                ['openid', self::OFFERED],
                self::NOT_OFFERED,
                'invalid_authorization_details',
            ],
            'a scope beyond the offer, an offered authorization detail' => [
                ['openid', self::NOT_OFFERED],
                self::OFFERED,
                'invalid_scope',
            ],
        ];
    }


    /**
     * @param string[] $scopes
     * @throws \Throwable
     */
    #[DataProvider('oneParameterBeyondTheOfferProvider')]
    public function testRefusesWhicheverParameterAsksBeyondTheOffer(
        array $scopes,
        string $authorizationDetail,
        string $errorType,
    ): void {
        $this->theOfferOffered([self::OFFERED]);

        $exception = $this->refusal($this->resultBag(
            scopes: $scopes,
            authorizationDetails: [$this->authorizationDetail($authorizationDetail)],
        ));

        $this->assertSame($errorType, $exception->getErrorType());
    }


    /**
     * An issuer state stored before the offered configurations were recorded offers none, and so does one which
     * is gone by the time this rule looks for it: nothing can be asked for after either, rather than anything.
     *
     * @return array<string,array{bool}>
     */
    public static function offersOfNothingProvider(): array
    {
        return [
            'an issuer state which recorded nothing' => [true],
            'an issuer state gone since IssuerStateRule found it' => [false],
        ];
    }


    /**
     * @throws \Throwable
     */
    #[DataProvider('offersOfNothingProvider')]
    public function testAnOfferOfNothingAdmitsNoConfiguration(bool $isFound): void
    {
        if ($isFound) {
            $this->theOfferOffered([]);
        } else {
            $this->issuerStateRepositoryMock->method('find')->with(self::ISSUER_STATE)->willReturn(null);
        }

        $this->assertSame(
            'invalid_scope',
            $this->refusal($this->resultBag(scopes: ['openid', self::OFFERED]))->getErrorType(),
        );
        $this->assertSame(
            'invalid_authorization_details',
            $this->refusal($this->resultBag(authorizationDetails: [$this->authorizationDetail(self::OFFERED)]))
                ->getErrorType(),
        );
    }


    /**
     * The issuer state is what lets a wallet redeem an offer, so it is kept out of the log.
     *
     * @throws \Throwable
     */
    public function testDoesNotLogTheIssuerState(): void
    {
        $this->theOfferOffered([self::OFFERED]);

        $this->refusal($this->resultBag(scopes: [self::NOT_OFFERED]));
        $this->refusal($this->resultBag(authorizationDetails: [$this->authorizationDetail(self::NOT_OFFERED)]));

        $this->assertNotSame([], $this->logRecords);
        $this->assertStringNotContainsString(self::ISSUER_STATE, json_encode($this->logRecords, JSON_THROW_ON_ERROR));
    }
}
