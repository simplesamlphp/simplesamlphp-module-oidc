<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IssuerStateRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * The rule which carries an authorization request's `issuer_state` into the result bag.
 *
 * It runs among the authorization request rules of `AuthCodeGrant`, which reads the value back from the
 * bag under the rule's key and sets it on the authorization request. The parameter is optional -- a
 * Wallet sends it when the Credential Offer it is acting on carried one, and a plain OpenID Connect
 * request never has one -- so the rule never refuses: absent, the result holds null. Nothing is logged and
 * nothing else in the bag is consulted; the rule is the one line which reads the parameter under the
 * methods it is told to allow.
 */
#[CoversClass(IssuerStateRule::class)]
#[AllowMockObjectsWithoutExpectations]
class IssuerStateRuleTest extends TestCase
{
    protected const string ISSUER_STATE = '3b4d8f1e6a2c9075d1e8f4a6b2c3d5e7f9a1b3c5d7e9f2a4b6c8d0e2f4a6b8c0';


    protected MockObject $requestParamsResolverMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $requestMock;


    protected function setUp(): void
    {
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
    }


    protected function sut(): IssuerStateRule
    {
        return new IssuerStateRule($this->requestParamsResolverMock, new Helpers());
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
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testReadsTheIssuerStateFromTheRequestUnderTheAllowedMethods(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAsStringBasedOnAllowedMethods')
            ->with(
                ParamsEnum::IssuerState->value,
                $this->identicalTo($this->requestMock),
                [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
            )
            ->willReturn(self::ISSUER_STATE);
        $this->loggerServiceMock->expects($this->never())->method($this->anything());

        $result = $this->sut()->checkRule(
            $this->requestMock,
            new ResultBag(),
            $this->loggerServiceMock,
            allowedServerRequestMethods: [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
        );

        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame(IssuerStateRule::class, $result->getKey());
        $this->assertSame(self::ISSUER_STATE, $result->getValue());
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testAllowsOnlyGetUnlessToldOtherwise(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAsStringBasedOnAllowedMethods')
            ->with(ParamsEnum::IssuerState->value, $this->identicalTo($this->requestMock), [HttpMethodsEnum::GET])
            ->willReturn(self::ISSUER_STATE);

        $result = $this->sut()->checkRule($this->requestMock, new ResultBag(), $this->loggerServiceMock);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame(IssuerStateRule::class, $result->getKey());
        $this->assertSame(self::ISSUER_STATE, $result->getValue());
    }


    /**
     * An absent parameter is a result holding null, not a refusal: the parameter is optional.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testAnAbsentIssuerStateIsAResultHoldingNull(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAsStringBasedOnAllowedMethods')
            ->with(ParamsEnum::IssuerState->value, $this->identicalTo($this->requestMock), [HttpMethodsEnum::GET])
            ->willReturn(null);

        $result = $this->sut()->checkRule($this->requestMock, new ResultBag(), $this->loggerServiceMock);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame(IssuerStateRule::class, $result->getKey());
        $this->assertNull($result->getValue());
    }
}
