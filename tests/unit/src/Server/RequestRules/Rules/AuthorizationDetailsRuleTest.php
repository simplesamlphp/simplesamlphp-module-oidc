<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AuthorizationDetailsRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

/**
 * The Rich Authorization Requests gate, from RFC 9396.
 *
 * The rule reads the `authorization_details` parameter, decodes it, and either hands the decoded value on
 * or refuses the request. It runs at the authorization endpoint from AuthCodeGrant and at the token
 * endpoint from PreAuthCodeGrant, and both of them read its result by this rule's own class name.
 *
 * Almost the whole of the class is one decision, and the decision is which malformed input is ignored and
 * which is refused:
 *
 * - Ignored, yielding no result at all: an absent parameter, a value which will not JSON decode, a value
 *   which decodes to something other than an array, and an empty array.
 * - Refused with an `invalid_request` error: the server not issuing credentials at all, a detail which is
 *   not an object, a detail with no type, a detail whose type is not `openid_credential`, and a detail
 *   with no credential configuration identifier.
 *
 * The order of those two groups is load bearing and reads like an accident. All four ignored cases are
 * settled before the rule ever asks whether Verifiable Credential Issuance is enabled, so on a server
 * which does not issue credentials a garbled `authorization_details` is dropped rather than rejected.
 * Hoisting the enabled check to the top would look like a tidy-up -- it is the cheapest of the five -- and
 * would turn a parameter a plain OpenID Connect server has never cared about into a hard failure. Each of
 * the four therefore has a test holding issuance disabled which still expects null, and there is one
 * going the other way, holding issuance disabled with a malformed detail, so the gate cannot drift below
 * the loop either.
 *
 * The five refusals are one exception class carrying one error code. Each names the offending parameter
 * at its throw site, but that name only ever serves as the fallback for a missing hint, and all five pass
 * an explicit hint, so the name is discarded and never reaches the client. The hint is therefore the only
 * thing separating one refusal from another, and every test below which expects a refusal asserts it.
 * Logging is deliberately not asserted anywhere; the rule logs each branch it takes, but the branch is
 * already the thing under test.
 */
#[CoversClass(AuthorizationDetailsRule::class)]
class AuthorizationDetailsRuleTest extends TestCase
{
    /**
     * The parameter name RFC 9396 fixes on the wire. Spelled out rather than read back from ParamsEnum, so
     * that a change to the enum case surfaces here as a failure instead of travelling silently with the
     * production code this is supposed to be checking.
     */
    protected const string PARAM = 'authorization_details';

    /**
     * The only authorization details type this server understands, fixed by OpenID4VCI.
     */
    protected const string VALID_TYPE = 'openid_credential';

    /**
     * Whatever the rule might ask the result bag for, it gets this back. See setUp().
     */
    protected const string AVAILABLE_IN_RESULT_BAG = 'https://client.example.org/cb';


    protected Stub $requestStub;

    protected Stub $resultBagStub;

    protected Stub $loggerServiceStub;

    protected Stub $moduleConfigStub;

    protected Stub $requestParamsResolverStub;

    protected Helpers $helpers;

    protected Stub $responseModeStub;


    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);

        // The rule reads nothing out of the bag, which is what lets it serve the token endpoint as well,
        // where the bag is empty. The stub still answers everything it might be asked, because otherwise
        // the redirect assertion in assertRefusedWithHint() could not fail: an unconfigured stub returns
        // null for get() and getOrFail(), so even a rule which had started reading a redirect URI out of
        // the bag would go on building an exception that carried none, and the assertion would hold
        // either way.
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->resultBagStub->method('get')->willReturnCallback(
            fn(string $key): Result => new Result($key, self::AVAILABLE_IN_RESULT_BAG),
        );
        $this->resultBagStub->method('getOrFail')->willReturnCallback(
            fn(string $key): Result => new Result($key, self::AVAILABLE_IN_RESULT_BAG),
        );
        $this->resultBagStub->method('getValueOrFail')->willReturn(self::AVAILABLE_IN_RESULT_BAG);
        $this->resultBagStub->method('has')->willReturn(true);

        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->helpers = new Helpers();
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
    }


    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
        ?ModuleConfig $moduleConfig = null,
    ): AuthorizationDetailsRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;
        $moduleConfig ??= $this->moduleConfigStub;

        return new AuthorizationDetailsRule($requestParamsResolver, $helpers, $moduleConfig);
    }


    /**
     * Run the rule over a raw `authorization_details` parameter value, with credential issuance either on
     * or off.
     *
     * The resolver stub here answers every call with the same value, which cannot tell which parameter was
     * asked for or with which allowed methods. That is what the two wiring tests below are for, and they
     * are the only ones which care; everywhere else the parameter's value is the subject and the lookup is
     * scaffolding. Those two set issuance explicitly even though the rule returns before the gate when
     * the parameter is absent, so it changes nothing as the code stands. It is there so that if the gate
     * ever moves above the parameter lookup, those two fail for a wiring reason or not at all, rather
     * than joining the ordering tests as collateral -- which is what they did before it was set.
     *
     * @throws \Throwable
     */
    protected function check(?string $parameterValue, bool $vciEnabled = true): ?Result
    {
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')
            ->willReturn($parameterValue);
        $this->moduleConfigStub->method('getVciEnabled')->willReturn($vciEnabled);

        return $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }


    /**
     * A single authorization detail the rule accepts.
     *
     * @return array<string, mixed>
     */
    protected function validDetail(string $credentialConfigurationId = 'UniversityDegree_JWT'): array
    {
        return [
            'type' => self::VALID_TYPE,
            'credential_configuration_id' => $credentialConfigurationId,
        ];
    }


    /**
     * @param array<mixed> $authorizationDetails
     * @throws \JsonException
     */
    protected function encode(array $authorizationDetails): string
    {
        return json_encode($authorizationDetails, JSON_THROW_ON_ERROR);
    }


    /**
     * The hint is the only thing separating one refusal from the next, so a test naming only the exception
     * class could not tell a missing type from an unknown one, nor either of those from the refusal to
     * accept Rich Authorization Requests at all -- and any one of the five guards could be deleted or
     * reordered with such a test still green.
     *
     * The rest of the shape is asserted here, for every refusal, rather than in one test of its own. Kept
     * in one test it would have covered a single guard, leaving the other four free to start attaching a
     * redirect, or answering with a different code or status, without anything failing.
     *
     * The redirect assertion pins something the rule does not do rather than something it does.
     * CodeChallengeRule, three positions earlier in the same rule list at the authorization endpoint,
     * reads the redirect URI and state out of the bag and passes them, along with the response mode it
     * was handed, into its own `invalidRequest` call, so its refusals travel back to the client as an
     * `error=invalid_request` redirect. This rule passes none of the three -- it accepts a response mode
     * and ignores it -- so its refusals surface as a bare 400 in the end user's browser instead. It
     * cannot simply copy the neighbour: it also runs at the token endpoint from PreAuthCodeGrant, which
     * predefines no bag, so reading those results would raise a LogicException there. Recorded so a later
     * fix has to come past these assertions deliberately, and the bag stub hands back a redirect URI for
     * the asking (see setUp), so they fail the moment the rule starts using one.
     *
     * @throws \Throwable
     */
    protected function assertRefusedWithHint(
        string $expectedHint,
        ?string $parameterValue,
        bool $vciEnabled = true,
    ): void {
        try {
            $this->check($parameterValue, $vciEnabled);
        } catch (OidcServerException $exception) {
            $this->assertSame($expectedHint, $exception->getHint());
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertSame(400, $exception->getHttpStatusCode());
            $this->assertFalse($exception->hasRedirect());

            return;
        }

        $this->fail('Expected the rule to refuse the request, but it returned instead.');
    }


    /**
     * @return array<string, array{array<int, \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum>}>
     */
    public static function allowedMethodsProvider(): array
    {
        return [
            'POST alone' => [[HttpMethodsEnum::POST]],
            'GET and POST, as the authorization endpoint sends' => [
                [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
            ],
        ];
    }


    /**
     * The rule reads one parameter, out of the request it was handed, using the methods its caller allows.
     * A stub which answers every call alike can tell none of that apart: it answers the same whether the
     * rule asks for `authorization_details` or for `scope`, and whether the rule forwards the caller's
     * allowed methods or quietly falls back to the GET-only default in its own signature. Neither row of
     * the provider is that default: the first for the sharpest possible contrast with it, the second
     * because it is what AuthCodeGrant forwards at the authorization endpoint, and nothing else here
     * passes more than one method.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     * @throws \Throwable
     */
    #[DataProvider('allowedMethodsProvider')]
    public function testAsksForTheAuthorizationDetailsParameterOfTheGivenRequestUsingTheAllowedMethods(
        array $allowedServerRequestMethods,
    ): void {
        $this->moduleConfigStub->method('getVciEnabled')->willReturn(true);

        $requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $requestParamsResolverMock->expects($this->once())
            ->method('getAsStringBasedOnAllowedMethods')
            ->with(
                self::PARAM,
                $this->identicalTo($this->requestStub),
                $allowedServerRequestMethods,
            )
            ->willReturn(null);

        $this->assertNull(
            $this->sut($requestParamsResolverMock)->checkRule(
                $this->requestStub,
                $this->resultBagStub,
                $this->loggerServiceStub,
                [],
                $this->responseModeStub,
                $allowedServerRequestMethods,
            ),
        );
    }


    /**
     * Called without a method list, the rule falls back to the default in its own signature. No production
     * caller leans on that default -- AuthCodeGrant forwards [GET, POST] and PreAuthCodeGrant forwards
     * [POST], both of them explicitly -- so this pins the signature and nothing more. It is here because
     * the test above always passes a list, and a default nothing exercises is a default nothing would
     * notice changing.
     *
     * @throws \Throwable
     */
    public function testFallsBackToGetWhenNoAllowedMethodsAreGiven(): void
    {
        $this->moduleConfigStub->method('getVciEnabled')->willReturn(true);

        $requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $requestParamsResolverMock->expects($this->once())
            ->method('getAsStringBasedOnAllowedMethods')
            ->with(
                self::PARAM,
                $this->identicalTo($this->requestStub),
                [HttpMethodsEnum::GET],
            )
            ->willReturn(null);

        $this->assertNull(
            $this->sut($requestParamsResolverMock)->checkRule(
                $this->requestStub,
                $this->resultBagStub,
                $this->loggerServiceStub,
                [],
                $this->responseModeStub,
            ),
        );
    }


    /**
     * @return array<string, array{bool}>
     */
    public static function vciEnabledProvider(): array
    {
        return [
            'issuance enabled' => [true],
            'issuance disabled' => [false],
        ];
    }


    /**
     * A request carrying no `authorization_details` at all is not a Rich Authorization Request, and the
     * rule leaves it alone. It yields no result rather than an empty one, which is what lets both grants
     * write `$resultBag->get(...)?->getValue()` and read back null.
     *
     * Run with issuance both ways. This is the first of the four ignored cases, and the one which would
     * take down every ordinary authorization request on a server that issues no credentials, were the
     * issuance gate ever hoisted above it.
     *
     * @throws \Throwable
     */
    #[DataProvider('vciEnabledProvider')]
    public function testYieldsNoResultWhenTheParameterIsAbsent(bool $vciEnabled): void
    {
        $this->assertNull($this->check(null, $vciEnabled));
    }


    /**
     * @throws \Throwable
     */
    public function testIgnoresUndecodableJsonEvenWhenVciIsDisabled(): void
    {
        $this->assertNull($this->check('{"type": "openid_credential"', vciEnabled: false));
    }


    /**
     * The string case is the valid type on its own, so a rule which went looking for the type in the raw
     * parameter text rather than in a decoded detail would not survive it.
     *
     * @return array<string, array{string}>
     */
    public static function nonArrayJsonProvider(): array
    {
        return [
            'string' => ['"' . self::VALID_TYPE . '"'],
            'number' => ['5'],
            'boolean' => ['true'],
            // Valid JSON, so nothing is thrown on the way in. This dataset alone cannot say which of the
            // two checks dropped it, since `empty(null)` is true as well; the three above it can.
            'null' => ['null'],
        ];
    }


    /**
     * @throws \Throwable
     */
    #[DataProvider('nonArrayJsonProvider')]
    public function testIgnoresANonArrayValueEvenWhenVciIsDisabled(string $parameterValue): void
    {
        $this->assertNull($this->check($parameterValue, vciEnabled: false));
    }


    /**
     * Both decode to the same empty array once objects are decoded as associative arrays.
     *
     * @return array<string, array{string}>
     */
    public static function emptyJsonProvider(): array
    {
        return [
            'empty array' => ['[]'],
            'empty object' => ['{}'],
        ];
    }


    /**
     * @throws \Throwable
     */
    #[DataProvider('emptyJsonProvider')]
    public function testIgnoresAnEmptyValueEvenWhenVciIsDisabled(string $parameterValue): void
    {
        $this->assertNull($this->check($parameterValue, vciEnabled: false));
    }


    /**
     * A well formed Rich Authorization Request is refused outright by a server which does not issue
     * credentials, rather than being dropped the way the malformed values above are. RFC 9396 asks for the
     * error; silently ignoring the parameter would let the client believe its request had been honoured.
     *
     * @throws \Throwable
     */
    public function testRefusesRichAuthorizationRequestsWhenVciIsDisabled(): void
    {
        $this->assertRefusedWithHint(
            'Rich Authorization Requests are not used by this server.',
            $this->encode([$this->validDetail()]),
            vciEnabled: false,
        );
    }


    /**
     * The issuance gate sits above the loop as well as below the four ignored cases, so a server which
     * issues no credentials says so rather than reporting whatever else is wrong with the detail. Were the
     * gate to drift below the loop, this request would come back as an unknown type instead.
     *
     * @throws \Throwable
     */
    public function testRefusesOnIssuanceBeingDisabledBeforeLookingAtTheDetails(): void
    {
        $detail = $this->validDetail();
        $detail['type'] = 'payment_initiation';

        $this->assertRefusedWithHint(
            'Rich Authorization Requests are not used by this server.',
            $this->encode([$detail]),
            vciEnabled: false,
        );
    }


    /**
     * @throws \Throwable
     */
    public function testRefusesADetailWhichIsNotAnObject(): void
    {
        $this->assertRefusedWithHint(
            'Malformed authorization_details parameter value.',
            $this->encode([self::VALID_TYPE]),
        );
    }


    /**
     * RFC 9396 puts a JSON array of objects in this parameter, and a client which sends one bare object
     * instead produces a PHP associative array -- still an array, so it passes the non-array check and the
     * empty check both, and reaches the loop, where its members are strings rather than details. The shape
     * error therefore surfaces as a malformed detail. Nothing in the class says so, and it is true only
     * because the check is `is_array` rather than `array_is_list`.
     *
     * @throws \Throwable
     */
    public function testRefusesASingleDetailObjectSentInPlaceOfAnArrayOfThem(): void
    {
        $this->assertRefusedWithHint(
            'Malformed authorization_details parameter value.',
            $this->encode($this->validDetail()),
        );
    }


    /**
     * @throws \Throwable
     */
    public function testRefusesADetailWithNoType(): void
    {
        $detail = $this->validDetail();
        unset($detail['type']);

        $this->assertRefusedWithHint(
            'Authorization details parameter value has no type.',
            $this->encode([$detail]),
        );
    }


    /**
     * `isset` reads false for a null value, so a detail whose type is present but null is refused as having
     * no type rather than as having an unknown one. The two guards are adjacent and their hints are all
     * that separates them, and this is the case which would cross from one to the other were `isset` ever
     * relaxed to `array_key_exists`.
     *
     * @throws \Throwable
     */
    public function testRefusesADetailWhoseTypeIsNull(): void
    {
        $detail = $this->validDetail();
        $detail['type'] = null;

        $this->assertRefusedWithHint(
            'Authorization details parameter value has no type.',
            $this->encode([$detail]),
        );
    }


    /**
     * @throws \Throwable
     */
    public function testRefusesADetailWithAnUnknownType(): void
    {
        $detail = $this->validDetail();
        $detail['type'] = 'payment_initiation';

        $this->assertRefusedWithHint(
            'Authorization details parameter value has unknown type.',
            $this->encode([$detail]),
        );
    }


    /**
     * @throws \Throwable
     */
    public function testRefusesADetailWithNoCredentialConfigurationId(): void
    {
        $detail = $this->validDetail();
        unset($detail['credential_configuration_id']);

        $this->assertRefusedWithHint(
            'Authorization details parameter value has no credential_configuration_id.',
            $this->encode([$detail]),
        );
    }


    /**
     * The same `isset` reading as for the type above, on the guard which follows it.
     *
     * @throws \Throwable
     */
    public function testRefusesADetailWhoseCredentialConfigurationIdIsNull(): void
    {
        $detail = $this->validDetail();
        $detail['credential_configuration_id'] = null;

        $this->assertRefusedWithHint(
            'Authorization details parameter value has no credential_configuration_id.',
            $this->encode([$detail]),
        );
    }


    /**
     * A detail can fail two guards at once, and only their order decides which the client hears about.
     * Every other refusal test here isolates its own guard, holding the rest of the detail valid, so none
     * of them constrains the order at all: this one does. With both the type and the credential
     * configuration identifier wrong, the type is reported, which is the more useful of the two, an
     * unknown type making the identifier moot.
     *
     * @throws \Throwable
     */
    public function testReportsAnUnknownTypeAheadOfAMissingCredentialConfigurationId(): void
    {
        $this->assertRefusedWithHint(
            'Authorization details parameter value has unknown type.',
            $this->encode([['type' => 'payment_initiation']]),
        );
    }


    /**
     * The loop has to reach every detail, not only the first. A rule which examined
     * `$authorizationDetails[0]` alone, or which stopped once a detail passed, would accept this request,
     * whose second detail names a type the server does not issue.
     *
     * @throws \Throwable
     */
    public function testRefusesADetailWhichIsNotTheFirst(): void
    {
        $second = $this->validDetail('SomethingElse');
        $second['type'] = 'payment_initiation';

        $this->assertRefusedWithHint(
            'Authorization details parameter value has unknown type.',
            $this->encode([$this->validDetail(), $second]),
        );
    }


    /**
     * The decoded value reaches the result bag as it arrived. The payload carries members the rule never
     * inspects -- `credential_definition` and `locations`, both of them OpenID4VCI's rather than this
     * module's -- and a second detail, so a rule which rebuilt the value out of the two members it does
     * inspect, or which kept only the first detail, could not produce this array. Comparing with
     * `assertSame` holds the ordering and the scalar types too.
     *
     * The key is asserted because it is what both grants fetch the result by.
     *
     * @throws \Throwable
     */
    public function testYieldsTheDecodedAuthorizationDetailsVerbatim(): void
    {
        $authorizationDetails = [
            $this->validDetail(),
            [
                'type' => self::VALID_TYPE,
                'credential_configuration_id' => 'org.iso.18013.5.1.mDL',
                'credential_definition' => ['type' => ['VerifiableCredential', 'UniversityDegree']],
                'locations' => ['https://op.example.org'],
            ],
        ];

        $result = $this->check($this->encode($authorizationDetails));

        $this->assertNotNull($result);
        $this->assertSame(AuthorizationDetailsRule::class, $result->getKey());
        $this->assertSame($authorizationDetails, $result->getValue());
    }
}
