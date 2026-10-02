<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\IssuerStateEntity;
use SimpleSAML\Module\oidc\Helpers;
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


    protected MockObject $requestParamsResolverMock;

    protected MockObject $issuerStateRepositoryMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $requestMock;

    protected MockObject $clientMock;

    /** @var array<int,array{level:string,message:string,context:array}> */
    protected array $logRecords = [];


    protected function setUp(): void
    {
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->issuerStateRepositoryMock = $this->createMock(IssuerStateRepository::class);
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
        return new IssuerStateRule($this->requestParamsResolverMock, new Helpers(), $this->issuerStateRepositoryMock);
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
