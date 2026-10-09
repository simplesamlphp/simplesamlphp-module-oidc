<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionProperty;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AuthorizationDetailsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

/**
 * The authorization_details parameter (RFC 9396), as OpenID4VCI 1.0 section 5.1.1 uses it.
 *
 * The rule reads the parameter, decodes it, and either hands the decoded value on or refuses the request with
 * invalid_authorization_details. It runs at the authorization and pushed authorization request endpoints, and at
 * the token endpoint from PreAuthCodeGrant; the grants read its result by this rule's own class name.
 *
 * The hint is what tells one refusal from another, so every refusal test asserts it; the rest of the shape (the
 * error code, the status, the redirect and the characters RFC 6749 section 5.2 allows in a description) is
 * asserted for every refusal too, in assertRefusedWith(). Logging is not asserted.
 */
#[CoversClass(AuthorizationDetailsRule::class)]
class AuthorizationDetailsRuleTest extends TestCase
{
    /**
     * Spelled out rather than read from ParamsEnum, so that a change to the enum surfaces here.
     */
    protected const string PARAM = 'authorization_details';

    protected const string VALID_TYPE = 'openid_credential';

    protected const string CONFIGURATION_ID = 'UniversityDegree_JWT';

    protected const string OTHER_CONFIGURATION_ID = 'SecondCredential';

    protected const string REDIRECT_URI = 'https://wallet.example.org/cb';

    protected const string STATE = 'state-123';

    protected const string NOT_AN_ARRAY_OF_DETAILS =
    'The authorization_details parameter is not a non-empty JSON array of authorization details.';

    protected const string RAR_NOT_USED = 'Rich Authorization Requests are not used by this server.';

    protected const string NOT_AN_OBJECT = 'An authorization detail is not a JSON object.';

    protected const string NO_TYPE = 'An authorization detail has no type.';

    protected const string UNKNOWN_TYPE =
    'An authorization detail is of a type this server does not support; the one it supports is ' .
    'openid_credential.';

    protected const string NO_CONFIGURATION_ID = 'An authorization detail has no credential_configuration_id.';

    protected const string CONFIGURATION_ID_NOT_A_STRING =
    'The credential_configuration_id of an authorization detail is not a non-empty string.';

    protected const string UNKNOWN_CONFIGURATION_ID =
    'An authorization detail names a credential configuration this issuer does not support.';

    protected const string CLAIMS_NOT_AN_ARRAY =
    'The claims of an authorization detail are not a non-empty array of claims descriptions.';

    protected const string CLAIMS_DESCRIPTION_NOT_AN_OBJECT =
    'A claims description of an authorization detail is not a JSON object.';

    protected const string NO_PATH =
    'A claims description of an authorization detail has no path which is a claims path pointer: a ' .
    'non-empty array of strings, nulls and non-negative integers.';

    protected const string MANDATORY_NOT_A_BOOLEAN =
    'The mandatory member of a claims description of an authorization detail is not a boolean.';

    protected const string CONTRADICTORY =
    'Two claims descriptions of an authorization detail contradict each other: one addresses an object ' .
    'member where another addresses an array, or all elements of an array where another addresses one of ' .
    'them.';

    protected const string REPEATED = 'Two claims descriptions of an authorization detail address the same claim.';


    protected Stub $requestStub;

    protected ResultBagInterface $resultBag;

    protected Stub $loggerServiceStub;

    protected Stub $moduleConfigStub;

    protected Stub $requestParamsResolverStub;

    protected Helpers $helpers;

    protected Stub $responseModeStub;


    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);

        // As at the authorization endpoint, where the client's redirect URI and the state are established before
        // the rule runs. The token endpoint's bag is empty (testDoesNotRedirectWhereNoRedirectUriIsEstablished).
        $this->resultBag = new ResultBag();
        $this->resultBag->add(new Result(ClientRedirectUriRule::class, self::REDIRECT_URI));
        $this->resultBag->add(new Result(StateRule::class, self::STATE));

        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->moduleConfigStub->method('getVciCredentialConfigurationIdsSupported')
            ->willReturn([self::CONFIGURATION_ID, self::OTHER_CONFIGURATION_ID]);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->helpers = new Helpers();
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
    }


    protected function sut(?RequestParamsResolver $requestParamsResolver = null): AuthorizationDetailsRule
    {
        return new AuthorizationDetailsRule(
            $requestParamsResolver ?? $this->requestParamsResolverStub,
            $this->helpers,
            $this->moduleConfigStub,
        );
    }


    /**
     * Run the rule over an authorization_details value: the serialized JSON a query or form parameter carries,
     * or the decoded value a Request Object claim holds. Without the parameter at all when it is not present.
     *
     * @throws \Throwable
     */
    protected function check(mixed $parameterValue, bool $vciEnabled = true, bool $present = true): ?Result
    {
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')
            ->willReturn($present ? [self::PARAM => $parameterValue, 'scope' => 'openid'] : ['scope' => 'openid']);
        $this->moduleConfigStub->method('getVciEnabled')->willReturn($vciEnabled);

        return $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }


    /**
     * @return array<string, mixed>
     */
    protected static function validDetail(string $credentialConfigurationId = self::CONFIGURATION_ID): array
    {
        return [
            'type' => self::VALID_TYPE,
            'credential_configuration_id' => $credentialConfigurationId,
        ];
    }


    /**
     * @throws \JsonException
     */
    protected static function encode(mixed $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR);
    }


    /**
     * A refusal is invalid_authorization_details (RFC 9396 section 5), sent back to the redirect URI with the
     * state and in the response mode the rule was given, where the redirect URI is established, as it is in
     * setUp(). Its description keeps to the characters RFC 6749 section 5.2 allows.
     *
     * @throws \Throwable
     */
    protected function assertRefusedWith(string $expectedHint, mixed $parameterValue, bool $vciEnabled = true): void
    {
        try {
            $this->check($parameterValue, $vciEnabled);
        } catch (OidcServerException $exception) {
            $this->assertSame($expectedHint, $exception->getHint());
            $this->assertSame('invalid_authorization_details', $exception->getErrorType());
            $this->assertSame(400, $exception->getHttpStatusCode());
            $this->assertSame(self::REDIRECT_URI, $exception->getRedirectUri());
            $this->assertSame(self::STATE, $exception->getPayload()['state'] ?? null);
            $this->assertSame(
                $this->responseModeStub,
                (new ReflectionProperty(OidcServerException::class, 'responseMode'))->getValue($exception),
            );
            $this->assertMatchesRegularExpression(
                '/^[\x20\x21\x23-\x5B\x5D-\x7E]*$/',
                (string)($exception->getPayload()['error_description'] ?? ''),
            );

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
     * The rule reads the parameters of the request it was handed, with the methods its caller allows. That it
     * reads authorization_details among them the tests which get a result show.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     * @throws \Throwable
     */
    #[DataProvider('allowedMethodsProvider')]
    public function testAsksForTheParametersOfTheGivenRequestUsingTheAllowedMethods(
        array $allowedServerRequestMethods,
    ): void {
        $this->moduleConfigStub->method('getVciEnabled')->willReturn(true);

        $requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->with($this->identicalTo($this->requestStub), $allowedServerRequestMethods)
            ->willReturn([]);

        $this->assertNull(
            $this->sut($requestParamsResolverMock)->checkRule(
                $this->requestStub,
                $this->resultBag,
                $this->loggerServiceStub,
                [],
                $this->responseModeStub,
                $allowedServerRequestMethods,
            ),
        );
    }


    /**
     * Called without a method list, the rule falls back to the default in its own signature.
     *
     * @throws \Throwable
     */
    public function testFallsBackToGetWhenNoAllowedMethodsAreGiven(): void
    {
        $this->moduleConfigStub->method('getVciEnabled')->willReturn(true);

        $requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->with($this->identicalTo($this->requestStub), [HttpMethodsEnum::GET])
            ->willReturn([]);

        $this->assertNull(
            $this->sut($requestParamsResolverMock)->checkRule(
                $this->requestStub,
                $this->resultBag,
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
     * A request without authorization_details is not a Rich Authorization Request: no result at all, which is
     * what lets the grants read null back.
     *
     * @throws \Throwable
     */
    #[DataProvider('vciEnabledProvider')]
    public function testYieldsNoResultWhenTheParameterIsAbsent(bool $vciEnabled): void
    {
        $this->assertNull($this->check(null, $vciEnabled, present: false));
    }


    /**
     * Values which are not a non-empty array of details: a serialized one which does not decode, or decodes to
     * something else, and a decoded one (a Request Object claim) which is not one, null included. A single detail
     * sent in place of an array of them is an object, not an array.
     *
     * @return array<string, array{mixed}>
     * @throws \JsonException
     */
    public static function notAnArrayOfDetailsProvider(): array
    {
        return [
            'undecodable JSON' => ['[{"type": "openid_credential"'],
            'a JSON string' => ['"' . self::VALID_TYPE . '"'],
            'a JSON number' => ['5'],
            'a JSON boolean' => ['true'],
            'JSON null' => ['null'],
            'an empty JSON array' => ['[]'],
            'an empty JSON object' => ['{}'],
            'a single detail object' => [self::encode(self::validDetail())],
            'a decoded boolean' => [true],
            // A Request Object claim written as null: present, so not taken for an absent parameter.
            'a decoded null' => [null],
            'a decoded empty array' => [[]],
            'a decoded single detail' => [self::validDetail()],
        ];
    }


    /**
     * A server which does not issue credentials does not use the parameter, so it ignores a value which is not
     * an array of details rather than refusing a plain OpenID Connect request for it (RFC 6749 section 3.1).
     *
     * @throws \Throwable
     */
    #[DataProvider('notAnArrayOfDetailsProvider')]
    public function testIgnoresAValueWhichIsNotAnArrayOfDetailsWhileNotIssuing(mixed $parameterValue): void
    {
        $this->assertNull($this->check($parameterValue, vciEnabled: false));
    }


    /**
     * A server which issues credentials refuses it: OpenID4VCI 1.0 section 5.1.1 makes it the parameter that
     * says which credentials are wanted, and dropping it would issue a token for none of them, or for the
     * scope's alone, without the wallet hearing why.
     *
     * @throws \Throwable
     */
    #[DataProvider('notAnArrayOfDetailsProvider')]
    public function testRefusesAValueWhichIsNotAnArrayOfDetailsWhileIssuing(mixed $parameterValue): void
    {
        $this->assertRefusedWith(self::NOT_AN_ARRAY_OF_DETAILS, $parameterValue);
    }


    /**
     * A server which does not issue credentials knows no type of authorization details, so it refuses an array
     * of them, whatever they say: the gate comes before any detail is looked at.
     *
     * @return array<string, array{mixed}>
     * @throws \JsonException
     */
    public static function arrayOfDetailsProvider(): array
    {
        return [
            'a valid detail' => [self::encode([self::validDetail()])],
            'a detail of another type' => [self::encode([['type' => 'payment_initiation']])],
            'a detail which is not an object' => [self::encode([self::VALID_TYPE])],
            'decoded details' => [[self::validDetail()]],
        ];
    }


    /**
     * @throws \Throwable
     */
    #[DataProvider('arrayOfDetailsProvider')]
    public function testRefusesAnArrayOfDetailsWhileNotIssuing(mixed $parameterValue): void
    {
        $this->assertRefusedWith(self::RAR_NOT_USED, $parameterValue, vciEnabled: false);
    }


    /**
     * One detail at a time: each case changes a valid detail in one way, and the request is refused for that.
     *
     * @return array<string, array{mixed, string}>
     */
    public static function faultyDetailProvider(): array
    {
        $without = function (string $member): array {
            $detail = self::validDetail();
            unset($detail[$member]);
            return $detail;
        };
        $with = fn(string $member, mixed $value): array => [...self::validDetail(), $member => $value];

        return [
            'a string' => [self::VALID_TYPE, self::NOT_AN_OBJECT],
            'a number' => [5, self::NOT_AN_OBJECT],
            'null' => [null, self::NOT_AN_OBJECT],
            'an array' => [[self::VALID_TYPE, self::CONFIGURATION_ID], self::NOT_AN_OBJECT],
            'no type' => [$without('type'), self::NO_TYPE],
            'a null type' => [$with('type', null), self::NO_TYPE],
            'another type' => [$with('type', 'payment_initiation'), self::UNKNOWN_TYPE],
            'a type which is not a string' => [$with('type', 5), self::UNKNOWN_TYPE],
            'no credential_configuration_id' => [$without('credential_configuration_id'), self::NO_CONFIGURATION_ID],
            'a null credential_configuration_id' => [
                $with('credential_configuration_id', null),
                self::NO_CONFIGURATION_ID,
            ],
            'an empty credential_configuration_id' => [
                $with('credential_configuration_id', ''),
                self::CONFIGURATION_ID_NOT_A_STRING,
            ],
            'a numeric credential_configuration_id' => [
                $with('credential_configuration_id', 5),
                self::CONFIGURATION_ID_NOT_A_STRING,
            ],
            'a credential_configuration_id which is an array' => [
                $with('credential_configuration_id', [self::CONFIGURATION_ID]),
                self::CONFIGURATION_ID_NOT_A_STRING,
            ],
            'an unknown credential_configuration_id' => [
                $with('credential_configuration_id', 'UnknownCredential'),
                self::UNKNOWN_CONFIGURATION_ID,
            ],
            'a credential_configuration_id in another case' => [
                $with('credential_configuration_id', strtolower(self::CONFIGURATION_ID)),
                self::UNKNOWN_CONFIGURATION_ID,
            ],
        ];
    }


    /**
     * @throws \Throwable
     */
    #[DataProvider('faultyDetailProvider')]
    public function testRefusesAFaultyDetail(mixed $detail, string $expectedHint): void
    {
        $this->assertRefusedWith($expectedHint, self::encode([$detail]));
    }


    /**
     * The same checks hold for decoded details, as a Request Object carries them.
     *
     * @throws \Throwable
     */
    #[DataProvider('faultyDetailProvider')]
    public function testRefusesAFaultyDecodedDetail(mixed $detail, string $expectedHint): void
    {
        $this->assertRefusedWith($expectedHint, [$detail]);
    }


    /**
     * Every detail is checked, not the first alone.
     *
     * @throws \Throwable
     */
    public function testRefusesAFaultyDetailWhichIsNotTheFirst(): void
    {
        $this->assertRefusedWith(
            self::UNKNOWN_CONFIGURATION_ID,
            self::encode([self::validDetail(), self::validDetail('UnknownCredential')]),
        );
    }


    /**
     * A detail failing two checks is refused for the one checked first: an unknown type makes the identifier
     * moot.
     *
     * @throws \Throwable
     */
    public function testReportsAnUnknownTypeAheadOfAMissingCredentialConfigurationId(): void
    {
        $this->assertRefusedWith(self::UNKNOWN_TYPE, self::encode([['type' => 'payment_initiation']]));
    }


    /**
     * The claims of a detail (OpenID4VCI 1.0 Appendix B.1): a non-empty array of claims description objects,
     * each with a path which is a claims path pointer into a JSON-based credential (Appendix C.1) and, if it has
     * one, a boolean mandatory; none repeating or contradicting another (Appendix B.3).
     *
     * @return array<string, array{mixed, string}>
     */
    public static function faultyClaimsProvider(): array
    {
        return [
            'claims a string' => ['given_name', self::CLAIMS_NOT_AN_ARRAY],
            'claims null' => [null, self::CLAIMS_NOT_AN_ARRAY],
            'claims empty' => [[], self::CLAIMS_NOT_AN_ARRAY],
            'claims an object' => [['path' => ['given_name']], self::CLAIMS_NOT_AN_ARRAY],
            'a description which is a string' => [['given_name'], self::CLAIMS_DESCRIPTION_NOT_AN_OBJECT],
            'a description which is null' => [[null], self::CLAIMS_DESCRIPTION_NOT_AN_OBJECT],
            'a description which is an array' => [[['given_name']], self::CLAIMS_DESCRIPTION_NOT_AN_OBJECT],
            'a description which is not the first' => [
                [['path' => ['given_name']], 'family_name'],
                self::CLAIMS_DESCRIPTION_NOT_AN_OBJECT,
            ],
            'no path' => [[['mandatory' => true]], self::NO_PATH],
            'a null path' => [[['path' => null]], self::NO_PATH],
            'an empty path' => [[['path' => []]], self::NO_PATH],
            'a path which is a string' => [[['path' => 'given_name']], self::NO_PATH],
            'a path which is an object' => [[['path' => ['claim' => 'given_name']]], self::NO_PATH],
            'a negative index' => [[['path' => ['nationalities', -1]]], self::NO_PATH],
            'a fractional index' => [[['path' => ['nationalities', 1.5]]], self::NO_PATH],
            'a boolean component' => [[['path' => ['nationalities', true]]], self::NO_PATH],
            'an object component' => [[['path' => ['address', ['locality' => null]]]], self::NO_PATH],
            'mandatory a string' => [
                [['path' => ['given_name'], 'mandatory' => 'true']],
                self::MANDATORY_NOT_A_BOOLEAN,
            ],
            'mandatory a number' => [[['path' => ['given_name'], 'mandatory' => 1]], self::MANDATORY_NOT_A_BOOLEAN],
            'mandatory null' => [[['path' => ['given_name'], 'mandatory' => null]], self::MANDATORY_NOT_A_BOOLEAN],
            'the same claim twice' => [[['path' => ['given_name']], ['path' => ['given_name']]], self::REPEATED],
            'the same claim twice, once mandatory' => [
                [['path' => ['given_name'], 'mandatory' => true], ['path' => ['given_name']]],
                self::REPEATED,
            ],
            'the same elements twice' => [
                [['path' => ['degrees', null, 'type']], ['path' => ['degrees', null, 'type']]],
                self::REPEATED,
            ],
            'the same claim twice, apart' => [
                [['path' => ['given_name']], ['path' => ['family_name']], ['path' => ['given_name']]],
                self::REPEATED,
            ],
            'every element and one element of an array' => [
                [['path' => ['nationalities', null]], ['path' => ['nationalities', 0]]],
                self::CONTRADICTORY,
            ],
            'one element and every element of an array' => [
                [['path' => ['degrees', 1, 'type']], ['path' => ['degrees', null, 'university']]],
                self::CONTRADICTORY,
            ],
            'an array and an object' => [
                [['path' => ['address', 0]], ['path' => ['address', 'locality']]],
                self::CONTRADICTORY,
            ],
            'every element of an array and an object' => [
                [['path' => ['address', 'locality']], ['path' => ['address', null]]],
                self::CONTRADICTORY,
            ],
            'a member named 0 and the index 0' => [
                [['path' => ['address', '0']], ['path' => ['address', 0]]],
                self::CONTRADICTORY,
            ],
            'a contradiction deeper down' => [
                [['path' => ['degrees', 0, 'type', 'code']], ['path' => ['degrees', 0, 'type', null]]],
                self::CONTRADICTORY,
            ],
        ];
    }


    /**
     * @throws \Throwable
     */
    #[DataProvider('faultyClaimsProvider')]
    public function testRefusesFaultyClaims(mixed $claims, string $expectedHint): void
    {
        $this->assertRefusedWith($expectedHint, self::encode([[...self::validDetail(), 'claims' => $claims]]));
    }


    /**
     * Claims descriptions the rule accepts, Appendix C.3's examples among them: members of one object, a claim
     * and a claim within it, one element and another of an array, members of every element, and keys of its own
     * (Appendix B.1 allows other keys).
     *
     * @return array<string, array{array<mixed>}>
     */
    public static function acceptedClaimsProvider(): array
    {
        return [
            'one claim' => [[['path' => ['given_name']]]],
            'mandatory either way' => [
                [['path' => ['given_name'], 'mandatory' => true], ['path' => ['family_name'], 'mandatory' => false]],
            ],
            'members of one object' => [
                [['path' => ['address', 'street_address']], ['path' => ['address', 'locality']]],
            ],
            'a claim and a claim within it' => [[['path' => ['address']], ['path' => ['address', 'locality']]]],
            'elements of an array' => [[['path' => ['nationalities', 0]], ['path' => ['nationalities', 1]]]],
            'members of every element' => [
                [['path' => ['degrees', null, 'type']], ['path' => ['degrees', null, 'university']]],
            ],
            'members of one element' => [[['path' => ['degrees', 0, 'type']], ['path' => ['degrees', 0]]]],
            'an empty member name' => [[['path' => ['']]]],
            'keys of its own' => [[['path' => ['given_name'], 'display' => [['name' => 'Given name']]]]],
        ];
    }


    /**
     * Accepted, and handed on as sent: the claims are not honoured, and the rule does not rewrite them.
     *
     * @param array<mixed> $claims
     * @throws \Throwable
     */
    #[DataProvider('acceptedClaimsProvider')]
    public function testAcceptsWellFormedClaims(array $claims): void
    {
        $authorizationDetails = [[...self::validDetail(), 'claims' => $claims]];

        $this->assertSame($authorizationDetails, $this->check(self::encode($authorizationDetails))?->getValue());
    }


    /**
     * Appendix B.3 is about the claims array of one detail: two details may describe the same claim, each for
     * its own credential.
     *
     * @throws \Throwable
     */
    public function testAcceptsTheSameClaimInTwoDetails(): void
    {
        $claims = [['path' => ['given_name']]];
        $authorizationDetails = [
            [...self::validDetail(), 'claims' => $claims],
            [...self::validDetail(self::OTHER_CONFIGURATION_ID), 'claims' => $claims],
        ];

        $this->assertSame($authorizationDetails, $this->check(self::encode($authorizationDetails))?->getValue());
    }


    /**
     * The decoded value reaches the result bag as it arrived, members the rule does not use included (OpenID4VCI
     * 1.0 section 5.1.1: an openid_credential detail is never invalid for an unknown member), keyed by the
     * rule's class name, which is what the grants fetch it by.
     *
     * @throws \Throwable
     */
    public function testYieldsTheDecodedAuthorizationDetailsVerbatim(): void
    {
        $authorizationDetails = [
            self::validDetail(),
            [
                'type' => self::VALID_TYPE,
                'credential_configuration_id' => self::OTHER_CONFIGURATION_ID,
                'credential_definition' => ['type' => ['VerifiableCredential', 'UniversityDegree']],
                'locations' => ['https://op.example.org'],
            ],
        ];

        $result = $this->check(self::encode($authorizationDetails));

        $this->assertNotNull($result);
        $this->assertSame(AuthorizationDetailsRule::class, $result->getKey());
        $this->assertSame($authorizationDetails, $result->getValue());
    }


    /**
     * In a Request Object, and so in a pushed request which used one, authorization_details is a claim holding
     * the JSON array itself rather than its serialization (RFC 9396 section 3).
     *
     * @throws \Throwable
     */
    public function testYieldsTheAuthorizationDetailsARequestObjectCarriesDecoded(): void
    {
        $authorizationDetails = [self::validDetail(), self::validDetail(self::OTHER_CONFIGURATION_ID)];

        $this->assertSame($authorizationDetails, $this->check($authorizationDetails)?->getValue());
    }


    /**
     * At the token endpoint (PreAuthCodeGrant) no rule has established a redirect URI or a state, and the refusal
     * is answered directly; the rule reads both without requiring them.
     *
     * @throws \Throwable
     */
    public function testDoesNotRedirectWhereNoRedirectUriIsEstablished(): void
    {
        $this->resultBag = new ResultBag();

        try {
            $this->check(self::encode([self::validDetail('UnknownCredential')]));
        } catch (OidcServerException $exception) {
            $this->assertSame(self::UNKNOWN_CONFIGURATION_ID, $exception->getHint());
            $this->assertSame('invalid_authorization_details', $exception->getErrorType());
            $this->assertFalse($exception->hasRedirect());
            $this->assertArrayNotHasKey('state', $exception->getPayload());

            return;
        }

        $this->fail('Expected the rule to refuse the request, but it returned instead.');
    }
}
