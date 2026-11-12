<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\IssuerStateEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\CredentialOfferRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IssuerStateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\CredentialOfferRecord;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Stringable;

/**
 * The rule which checks an authorization request's `issuer_state` and carries it into the result bag.
 *
 * `AuthCodeGrant` reads the value back from the bag under the rule's key and sets it on the authorization
 * request, and the pushed authorization request endpoint runs the rule too. In an OpenID4VCI request the
 * parameter has to name a Credential Offer which can still be redeemed, and a request naming any other is
 * refused before the End-User logs in. Absent, or in a request which is not an OpenID4VCI one, it is no reason
 * to refuse anything: the result holds null.
 */
#[CoversClass(IssuerStateRule::class)]
#[AllowMockObjectsWithoutExpectations]
class IssuerStateRuleTest extends TestCase
{
    protected const string ISSUER_STATE = '3b4d8f1e6a2c9075d1e8f4a6b2c3d5e7f9a1b3c5d7e9f2a4b6c8d0e2f4a6b8c0';

    protected const string REDIRECT_URI = 'https://wallet.example.org/callback';

    protected const string STATE = 'state-of-the-wallet';

    protected const string CLIENT_ID = 'wallet-client-id';

    protected const string OFFER_ID = 'offer-1';


    protected MockObject $requestParamsResolverMock;

    protected MockObject $issuerStateRepositoryMock;

    protected MockObject $credentialOfferRepositoryMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $requestMock;

    protected MockObject $clientMock;

    /** @var array<int,array{level:string,message:string,context:array}> */
    protected array $logRecords = [];


    protected function setUp(): void
    {
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->issuerStateRepositoryMock = $this->createMock(IssuerStateRepository::class);
        $this->credentialOfferRepositoryMock = $this->createMock(CredentialOfferRepository::class);
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


    protected function sut(): IssuerStateRule
    {
        return new IssuerStateRule(
            $this->requestParamsResolverMock,
            new Helpers(),
            $this->issuerStateRepositoryMock,
            $this->credentialOfferRepositoryMock,
        );
    }


    /**
     * What the authorization endpoint has resolved before this rule runs: the client, its redirect URI and the
     * state, which an error is sent back with.
     */
    protected function resultBag(): ResultBag
    {
        $resultBag = new ResultBag();
        $resultBag->add(new Result(ClientRule::class, $this->clientMock));
        $resultBag->add(new Result(ClientRedirectUriRule::class, self::REDIRECT_URI));
        $resultBag->add(new Result(StateRule::class, self::STATE));

        return $resultBag;
    }


    /**
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $methods
     */
    protected function requestCarries(
        ?string $issuerState,
        bool $isVciRequest = true,
        array $methods = [HttpMethodsEnum::GET],
    ): void {
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')
            ->with(ParamsEnum::IssuerState->value, $this->identicalTo($this->requestMock), $methods)
            ->willReturn($issuerState);
        $this->requestParamsResolverMock->method('isVciAuthorizationCodeRequest')
            ->with($this->identicalTo($this->requestMock), $methods)
            ->willReturn($isVciRequest);
    }


    protected function offerCanBeRedeemed(bool $canBeRedeemed): void
    {
        $this->issuerStateRepositoryMock->method('findValid')
            ->with(self::ISSUER_STATE)
            ->willReturn($canBeRedeemed ? $this->createStub(IssuerStateEntity::class) : null);
    }


    protected function issuerStateNamesOffer(?string $offerId): void
    {
        $state = $this->createStub(IssuerStateEntity::class);
        $state->method('getOfferId')->willReturn($offerId);
        $this->issuerStateRepositoryMock->method('findValid')
            ->with(self::ISSUER_STATE)
            ->willReturn($state);
    }


    protected function offerRecord(bool $withdrawn): CredentialOfferRecord
    {
        $now = new DateTimeImmutable();

        return new CredentialOfferRecord(
            self::OFFER_ID,
            null,
            ['credential-configuration-id'],
            'authorization_code',
            $now,
            $now->modify('+5 minutes'),
            $now->modify('+1 day'),
            null,
            $withdrawn ? $now : null,
        );
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(IssuerStateRule::class, $this->sut());
    }


    /**
     * The key is the class name, which is what `AuthCodeGrant` asks the result bag for.
     */
    public function testIsKeyedByItsClassName(): void
    {
        $this->assertSame(IssuerStateRule::class, $this->sut()->getKey());
    }


    /**
     * @throws \Throwable
     */
    public function testCarriesAnIssuerStateWhoseOfferCanStillBeRedeemed(): void
    {
        $this->requestCarries(self::ISSUER_STATE, methods: [HttpMethodsEnum::GET, HttpMethodsEnum::POST]);
        $this->offerCanBeRedeemed(true);

        $result = $this->sut()->checkRule(
            $this->requestMock,
            $this->resultBag(),
            $this->loggerServiceMock,
            allowedServerRequestMethods: [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
        );

        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame(IssuerStateRule::class, $result->getKey());
        $this->assertSame(self::ISSUER_STATE, $result->getValue());
    }


    /**
     * @throws \Throwable
     */
    public function testAllowsOnlyGetUnlessToldOtherwise(): void
    {
        $this->requestCarries(self::ISSUER_STATE);
        $this->offerCanBeRedeemed(true);

        $result = $this->sut()->checkRule($this->requestMock, $this->resultBag(), $this->loggerServiceMock);

        $this->assertSame(self::ISSUER_STATE, $result?->getValue());
    }


    /**
     * An absent parameter is a result holding null, not a refusal: the parameter is optional.
     *
     * @throws \Throwable
     */
    public function testAnAbsentIssuerStateIsAResultHoldingNull(): void
    {
        $this->requestCarries(null);
        $this->issuerStateRepositoryMock->expects($this->never())->method('findValid');

        $result = $this->sut()->checkRule($this->requestMock, new ResultBag(), $this->loggerServiceMock);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame(IssuerStateRule::class, $result->getKey());
        $this->assertNull($result->getValue());
    }


    /**
     * A request which is not an OpenID4VCI one -- Verifiable Credential issuance switched off, or a response
     * type other than code -- follows no offer. The parameter means nothing there, and is neither checked nor
     * carried on, as an unknown parameter is ignored (RFC 6749 section 3.1).
     *
     * @throws \Throwable
     */
    public function testIgnoresTheIssuerStateOfARequestWhichIsNotAnOpenId4VciOne(): void
    {
        $this->requestCarries(self::ISSUER_STATE, isVciRequest: false);
        $this->issuerStateRepositoryMock->expects($this->never())->method('findValid');

        $result = $this->sut()->checkRule($this->requestMock, new ResultBag(), $this->loggerServiceMock);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertNull($result->getValue());
    }


    /**
     * An issuer state which names no offer that can still be redeemed -- one this issuer never made, one which
     * expired, or one already redeemed -- is refused before the End-User logs in. A registered client was
     * accepted on its own merits, so the error goes back to its redirect URI with the state, as any other
     * refusal of the request does.
     *
     * @throws \Throwable
     */
    public function testRefusesAnIssuerStateWhoseOfferCanNotBeRedeemedBackToARegisteredClient(): void
    {
        $this->requestCarries(self::ISSUER_STATE);
        $this->offerCanBeRedeemed(false);
        $this->clientMock->method('isGeneric')->willReturn(false);

        try {
            $this->sut()->checkRule($this->requestMock, $this->resultBag(), $this->loggerServiceMock);
            $this->fail('An issuer state whose offer can not be redeemed must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertSame(self::REDIRECT_URI, $exception->getRedirectUri());
            $this->assertSame(self::STATE, $exception->getPayload()['state'] ?? null);
        }

        $this->assertSame(
            [
                [
                    'level' => 'notice',
                    'message' => 'Authorization request rejected: `issuer_state` names no Credential Offer which ' .
                        'can still be redeemed.',
                    'context' => ['client_id' => self::CLIENT_ID],
                ],
            ],
            $this->logRecords,
        );
    }


    /**
     * The generic client, and the redirect URI it came with, were accepted only because the request carries an
     * issuer state. With that refuted the error is shown at the server rather than sent to the redirect URI
     * (RFC 6749 section 4.1.2.1).
     *
     * @throws \Throwable
     */
    public function testRefusesAnIssuerStateWhoseOfferCanNotBeRedeemedWithoutRedirectingTheGenericClient(): void
    {
        $this->requestCarries(self::ISSUER_STATE);
        $this->offerCanBeRedeemed(false);
        $this->clientMock->method('isGeneric')->willReturn(true);

        try {
            $this->sut()->checkRule($this->requestMock, $this->resultBag(), $this->loggerServiceMock);
            $this->fail('An issuer state whose offer can not be redeemed must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertFalse($exception->hasRedirect());
        }
    }


    /**
     * An offer its maker has withdrawn can not be redeemed, so the issuer state which would redeem it is refused
     * as one which names no offer is, and the error goes back to a registered client's redirect URI.
     *
     * @throws \Throwable
     */
    public function testRefusesAnIssuerStateWhoseOfferWasWithdrawnBackToARegisteredClient(): void
    {
        $this->requestCarries(self::ISSUER_STATE);
        $this->issuerStateNamesOffer(self::OFFER_ID);
        $this->credentialOfferRepositoryMock->expects($this->once())->method('find')->with(self::OFFER_ID)
            ->willReturn($this->offerRecord(withdrawn: true));
        $this->clientMock->method('isGeneric')->willReturn(false);

        try {
            $this->sut()->checkRule($this->requestMock, $this->resultBag(), $this->loggerServiceMock);
            $this->fail('An issuer state whose offer was withdrawn must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertSame(self::REDIRECT_URI, $exception->getRedirectUri());
            $this->assertSame(self::STATE, $exception->getPayload()['state'] ?? null);
        }

        // The refusal is the one logged for an issuer state which names no redeemable offer, and an info line says
        // why, naming the offer and never the issuer state.
        $this->assertContains(
            [
                'level' => 'info',
                'message' => 'IssuerStateRule: the Credential Offer the issuer state redeems has been withdrawn.',
                'context' => ['offerId' => self::OFFER_ID],
            ],
            $this->logRecords,
        );
        $this->assertSame(
            [
                [
                    'level' => 'notice',
                    'message' => 'Authorization request rejected: `issuer_state` names no Credential Offer which ' .
                        'can still be redeemed.',
                    'context' => ['client_id' => self::CLIENT_ID],
                ],
            ],
            array_values(array_filter(
                $this->logRecords,
                fn(array $record): bool => $record['level'] === 'notice',
            )),
        );
    }


    /**
     * As for an offer which can not be redeemed for another reason: the generic client is not redirected.
     *
     * @throws \Throwable
     */
    public function testRefusesAnIssuerStateWhoseOfferWasWithdrawnWithoutRedirectingTheGenericClient(): void
    {
        $this->requestCarries(self::ISSUER_STATE);
        $this->issuerStateNamesOffer(self::OFFER_ID);
        $this->credentialOfferRepositoryMock->expects($this->once())->method('find')->with(self::OFFER_ID)
            ->willReturn($this->offerRecord(withdrawn: true));
        $this->clientMock->method('isGeneric')->willReturn(true);

        try {
            $this->sut()->checkRule($this->requestMock, $this->resultBag(), $this->loggerServiceMock);
            $this->fail('An issuer state whose offer was withdrawn must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertFalse($exception->hasRedirect());
        }
    }


    /**
     * @throws \Throwable
     */
    public function testCarriesAnIssuerStateWhoseOfferWasNotWithdrawn(): void
    {
        $this->requestCarries(self::ISSUER_STATE);
        $this->issuerStateNamesOffer(self::OFFER_ID);
        $this->credentialOfferRepositoryMock->expects($this->once())->method('find')->with(self::OFFER_ID)
            ->willReturn($this->offerRecord(withdrawn: false));

        $result = $this->sut()->checkRule($this->requestMock, $this->resultBag(), $this->loggerServiceMock);

        $this->assertSame(self::ISSUER_STATE, $result?->getValue());
    }


    /**
     * An offer which is not recorded is left to the token endpoint, which refuses it as this server's fault.
     *
     * @throws \Throwable
     */
    public function testLeavesAnOfferWhichIsNotRecordedToTheTokenEndpoint(): void
    {
        $this->requestCarries(self::ISSUER_STATE);
        $this->issuerStateNamesOffer(self::OFFER_ID);
        $this->credentialOfferRepositoryMock->expects($this->once())->method('find')->with(self::OFFER_ID)
            ->willReturn(null);

        $result = $this->sut()->checkRule($this->requestMock, $this->resultBag(), $this->loggerServiceMock);

        $this->assertSame(self::ISSUER_STATE, $result?->getValue());
    }


    /**
     * @throws \Throwable
     */
    public function testLooksUpNoOfferForAnIssuerStateWhichNamesNone(): void
    {
        $this->requestCarries(self::ISSUER_STATE);
        $this->issuerStateNamesOffer(null);
        $this->credentialOfferRepositoryMock->expects($this->never())->method('find');

        $result = $this->sut()->checkRule($this->requestMock, $this->resultBag(), $this->loggerServiceMock);

        $this->assertSame(self::ISSUER_STATE, $result?->getValue());
    }


    /**
     * @throws \Throwable
     */
    public function testLooksUpNoOfferForAnIssuerStateWhichCanNotBeRedeemed(): void
    {
        $this->requestCarries(self::ISSUER_STATE);
        $this->offerCanBeRedeemed(false);
        $this->clientMock->method('isGeneric')->willReturn(true);
        $this->credentialOfferRepositoryMock->expects($this->never())->method('find');

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule($this->requestMock, $this->resultBag(), $this->loggerServiceMock);
    }


    /**
     * An offer which can not be read is neither a withdrawn one nor a redeemable one: it is this server's fault.
     *
     * @throws \Throwable
     */
    public function testAnswersAnOfferWhichCanNotBeReadAsAServerError(): void
    {
        $this->requestCarries(self::ISSUER_STATE);
        $this->issuerStateNamesOffer(self::OFFER_ID);
        $this->credentialOfferRepositoryMock->method('find')
            ->willThrowException(new RuntimeException('Database error'));

        try {
            $this->sut()->checkRule($this->requestMock, $this->resultBag(), $this->loggerServiceMock);
            $this->fail('An offer which can not be read must fail the request.');
        } catch (OidcServerException $exception) {
            $this->assertSame('server_error', $exception->getErrorType());
        }

        $this->assertContains(
            [
                'level' => 'error',
                'message' => 'IssuerStateRule: the Credential Offer the issuer state redeems could not be read.',
                'context' => ['offerId' => self::OFFER_ID, 'error' => 'Database error'],
            ],
            $this->logRecords,
        );
    }


    /**
     * The issuer state is what lets a wallet redeem an offer, so it is kept out of the log.
     *
     * @throws \Throwable
     */
    public function testDoesNotLogTheIssuerState(): void
    {
        $this->requestCarries(self::ISSUER_STATE);
        $this->offerCanBeRedeemed(false);
        $this->clientMock->method('isGeneric')->willReturn(false);

        try {
            $this->sut()->checkRule($this->requestMock, $this->resultBag(), $this->loggerServiceMock);
        } catch (OidcServerException) {
        }

        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->requestCarries(self::ISSUER_STATE, isVciRequest: false);
        $this->sut()->checkRule($this->requestMock, $this->resultBag(), $this->loggerServiceMock);

        $this->assertNotSame([], $this->logRecords);
        $this->assertStringNotContainsString(self::ISSUER_STATE, json_encode($this->logRecords, JSON_THROW_ON_ERROR));
    }
}
