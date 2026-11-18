<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseTypeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

#[CoversClass(ResponseTypeRule::class)]
#[AllowMockObjectsWithoutExpectations]
class ResponseTypeRuleTest extends TestCase
{
    protected Stub $requestStub;

    protected Stub $requestParamsResolverStub;

    protected Helpers $helpers;

    protected array $requestParams = [
        'client_id' => 'client123',
        'response_type' => '',
    ];

    protected array $sampleResponseTypes = [
        'should_add' => [
            'id_token',
        ],
        'should_not_add' => [
            'code',
            'token',
            'id_token token',
            'code id_token',
            'code token',
            'code id_token token',
        ],
    ];

    /**
     * @var \SimpleSAML\Module\oidc\Server\RequestRules\ResultBag
     */
    private ResultBag $resultBag;

    protected Stub $loggerServiceStub;

    protected Stub $responseModeStub;

    protected Stub $moduleConfigStub;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);

        $this->resultBag = new ResultBag();
        // The rule reads the resolved client; by default it has no registered response_types, so per-client
        // enforcement does not apply (preserving the previous behavior).
        $clientStub = $this->createStub(ClientEntityInterface::class);
        $clientStub->method('getResponseTypes')->willReturn([]);
        $this->resultBag->add(new Result(ClientRule::class, $clientStub));
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->helpers = new Helpers();
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
        // Every grant type enabled: the OP offers all three response types.
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->moduleConfigStub->method('getSupportedResponseTypes')
            ->willReturn(['code', 'id_token', 'id_token token']);
    }


    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
    ): ResponseTypeRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;

        return new ResponseTypeRule(
            $requestParamsResolver,
            $helpers,
            $this->moduleConfigStub,
        );
    }


    /**
     * A result bag with the resolved client, its redirect URI and the state, as AuthorizationServer leaves it before
     * a grant runs this rule.
     *
     * @param string[] $registeredResponseTypes
     */
    protected function bagForAClientRegisteredWith(array $registeredResponseTypes): ResultBag
    {
        $client = $this->createStub(ClientEntityInterface::class);
        $client->method('getResponseTypes')->willReturn($registeredResponseTypes);

        $bag = new ResultBag();
        $bag->add(new Result(ClientRule::class, $client));
        $bag->add(new Result(ClientRedirectUriRule::class, 'https://client.example.org/cb'));
        $bag->add(new Result(StateRule::class, 'state123'));

        return $bag;
    }


    /**
     * A response type the OP does not offer is refused as one the authorization server does not support, as RFC 6749
     * section 3.1.1 has one which is not understood refused, whoever the client is - one which registered no response
     * types included, and one which registered a response type the request contains. Grant selection lets such a
     * value through: the implicit grant takes any with `id_token` and without `code` in it. Values are separated by a
     * single space and each named once, so a doubled space or a repeated value is not understood either.
     *
     * @param string[] $registeredResponseTypes
     */
    #[DataProvider('responseTypeNotOfferedProvider')]
    public function testRefusesAResponseTypeTheOpDoesNotOfferWhoeverTheClientIs(
        string $responseType,
        array $registeredResponseTypes,
    ): void {
        $this->requestParams['response_type'] = $responseType;
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($this->requestParams);

        try {
            $this->sut()->checkRule(
                $this->requestStub,
                $this->bagForAClientRegisteredWith($registeredResponseTypes),
                $this->loggerServiceStub,
                [],
                $this->responseModeStub,
            );
            $this->fail('A response type the OP does not offer was accepted.');
        } catch (OidcServerException $exception) {
            $this->assertSame('unsupported_response_type', $exception->getErrorType());
            $this->assertSame('https://client.example.org/cb', $exception->getRedirectUri());
            $this->assertSame('state123', $exception->getPayload()['state'] ?? null);
        }
    }


    public static function responseTypeNotOfferedProvider(): array
    {
        return [
            'an extension value beside id_token, no response types registered' => ['id_token example_extension', []],
            'an extension value beside id_token, id_token registered' => ['id_token example_extension', ['id_token']],
            'token alone' => ['token', []],
            'a doubled space' => ['id_token  token', []],
            'a repeated value' => ['id_token id_token', ['id_token']],
            'the empty string' => ['', []],
        ];
    }


    /**
     * A response type longer than any the OP offers is refused without being split: a request can carry a value of
     * any length, and one of spaces would otherwise become an array as long as itself.
     */
    public function testDoesNotSplitAResponseTypeLongerThanAnyOffered(): void
    {
        $this->requestParams['response_type'] = 'id_token ' . str_repeat(' ', 10000) . 'token';
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($this->requestParams);
        $sut = new class (
            $this->requestParamsResolverStub,
            $this->helpers,
            $this->moduleConfigStub,
        ) extends ResponseTypeRule {
            /** @var string[] What was split into its values. */
            public array $split = [];


            protected function valuesOf(string $responseType): array
            {
                $this->split[] = $responseType;

                return parent::valuesOf($responseType);
            }
        };

        try {
            $sut->checkRule(
                $this->requestStub,
                $this->bagForAClientRegisteredWith([]),
                $this->loggerServiceStub,
                [],
                $this->responseModeStub,
            );
            $this->fail('A response type longer than any offered was accepted.');
        } catch (OidcServerException $exception) {
            $this->assertSame('unsupported_response_type', $exception->getErrorType());
        }

        $this->assertNotContains($this->requestParams['response_type'], $sut->split);
    }


    /**
     * A response type the implicit grant is disabled for is not offered either, and so not served whatever the
     * client registered.
     */
    public function testRefusesAResponseTypeOfAGrantWhichIsNotEnabled(): void
    {
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->moduleConfigStub->method('getSupportedResponseTypes')->willReturn(['code']);
        $this->requestParams['response_type'] = 'id_token';
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($this->requestParams);

        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('The response type is not supported by the authorization server.');

        $this->sut()->checkRule(
            $this->requestStub,
            $this->bagForAClientRegisteredWith(['id_token']),
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }


    /**
     * The values of a composite response type may come in any order (RFC 6749 section 3.1.1), for the OP's offer and
     * for the client's registration alike, and the rule answers the response type in the form the OP offers it,
     * which the rules after it compare with.
     *
     * @param string[] $registeredResponseTypes
     */
    #[DataProvider('valuesInAnotherOrderProvider')]
    public function testTakesTheValuesOfAResponseTypeInAnyOrder(array $registeredResponseTypes): void
    {
        $this->requestParams['response_type'] = 'token id_token';
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($this->requestParams);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->bagForAClientRegisteredWith($registeredResponseTypes),
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertSame('id_token token', $result?->getValue());
    }


    public static function valuesInAnotherOrderProvider(): array
    {
        return [
            'no response types registered' => [[]],
            'registered in the form the OP offers it' => [['code', 'id_token token']],
        ];
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('validResponseTypeProvider')]
    public function testResponseTypeRuleTest($responseType)
    {
        $this->requestParams['response_type'] = $responseType;
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($this->requestParams);
        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        ) ??
        new Result(ResponseTypeRule::class, null);
        $this->assertSame($responseType, $result->getValue());
    }


    public static function validResponseTypeProvider(): array
    {
        return [
            ['id_token'],
            ['code'],
        ];
    }


    /**
     * A response type the OP supports and the client did not register is the client's to be refused, not the
     * server's: `unauthorized_client` (RFC 6749 sections 4.1.2.1 and 4.2.2.1), not `unsupported_response_type`,
     * which is for a response type the OP does not support at all. It goes back to the client's redirect URI with
     * its state, as the other errors of the authorization endpoint do.
     */
    public function testRejectsResponseTypeNotRegisteredForClient(): void
    {
        $client = $this->createStub(ClientEntityInterface::class);
        $client->method('getResponseTypes')->willReturn(['code']);

        $bag = new ResultBag();
        $bag->add(new Result(ClientRule::class, $client));
        $bag->add(new Result(ClientRedirectUriRule::class, 'https://client.example.org/cb'));
        $bag->add(new Result(StateRule::class, 'state123'));

        $this->requestParams['response_type'] = 'id_token';
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($this->requestParams);

        try {
            $this->sut()->checkRule(
                $this->requestStub,
                $bag,
                $this->loggerServiceStub,
                [],
                $this->responseModeStub,
            );
            $this->fail('A response type the client did not register was accepted.');
        } catch (OidcServerException $exception) {
            $this->assertSame('unauthorized_client', $exception->getErrorType());
            $this->assertSame('The response type is not registered for the client.', $exception->getHint());
            $this->assertSame('https://client.example.org/cb', $exception->getRedirectUri());
            $this->assertSame('state123', $exception->getPayload()['state'] ?? null);
        }
    }


    public function testEmptyRegisteredResponseTypesIsNotEnforced(): void
    {
        // A present-but-empty response_types list means "not configured / unconstrained", not "allow nothing".
        // This preserves behavior for pre-DCR clients that get an empty list persisted on an admin save.
        $client = $this->createStub(ClientEntityInterface::class);
        $client->method('getResponseTypes')->willReturn([]);

        $bag = new ResultBag();
        $bag->add(new Result(ClientRule::class, $client));

        $this->requestParams['response_type'] = 'id_token';
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($this->requestParams);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $bag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertSame('id_token', $result?->getValue());
    }


    /**
     * A request without a response type is not judged: no grant takes it, so the authorization endpoint refuses it as
     * one no grant takes, and the pushed authorization request endpoint as one missing a parameter. The rule runs
     * before either, so it must not refuse it in some other way first.
     */
    public function testDoesNotJudgeARequestWithoutAResponseType(): void
    {
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn(['client_id' => '123']);

        $this->assertNull($this->sut()->checkRule(
            $this->requestStub,
            $this->bagForAClientRegisteredWith(['code']),
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        ));
    }


    /**
     * A response type which is not a string - an array from the query, a number from a Request Object - is not
     * understood, and refused as one which is not offered, to the redirect URI: at the pushed authorization request
     * endpoint it would otherwise be stored for a request_uri no grant can redeem.
     */
    #[DataProvider('responseTypeWhichIsNotAStringProvider')]
    public function testRefusesAResponseTypeWhichIsNotAString(mixed $responseType): void
    {
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')
            ->willReturn(['client_id' => '123', 'response_type' => $responseType]);

        try {
            $this->sut()->checkRule(
                $this->requestStub,
                $this->bagForAClientRegisteredWith([]),
                $this->loggerServiceStub,
                [],
                $this->responseModeStub,
            );
            $this->fail('A response type which is not a string was accepted.');
        } catch (OidcServerException $exception) {
            $this->assertSame('unsupported_response_type', $exception->getErrorType());
            $this->assertSame('https://client.example.org/cb', $exception->getRedirectUri());
        }
    }


    public static function responseTypeWhichIsNotAStringProvider(): array
    {
        return [
            'an array' => [['code']],
            'a number' => [1],
            'false' => [false],
        ];
    }


    /**
     * The client is the one ClientRule resolved, which the pushed authorization request endpoint knows from the
     * client's authentication: the client_id parameter is not read, and a request without one is judged all the same.
     */
    public function testJudgesTheResponseTypeOfARequestWithoutAClientIdParameter(): void
    {
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')
            ->willReturn(['response_type' => 'code']);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->bagForAClientRegisteredWith(['code']),
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertSame('code', $result?->getValue());
    }
}
