<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use LogicException;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AddClaimsToIdTokenRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseTypeRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AddClaimsToIdTokenRule
 */
class AddClaimsToIdTokenRuleTest extends TestCase
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
            'code',
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

    private ResultBag $resultBag;

    private Stub $loggerServiceStub;
    private Stub $responseModeStub;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);

        $this->resultBag = new ResultBag();
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->helpers = new Helpers();
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
    }

    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
    ): AddClaimsToIdTokenRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;

        return new AddClaimsToIdTokenRule(
            $requestParamsResolver,
            $helpers,
        );
    }

    /**
     * @dataProvider validResponseTypeProvider
     * @throws \Throwable
     */
    public function testAddClaimsToIdTokenRuleTest($responseType)
    {
        $this->resultBag->add(new Result(ResponseTypeRule::class, $responseType));

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        ) ??
        new Result(AddClaimsToIdTokenRule::class, null);
        $this->assertTrue($result->getValue());
    }

    public static function validResponseTypeProvider(): array
    {
        return [
            ['id_token'],
        ];
    }

    /**
     * @dataProvider invalidResponseTypeProvider
     * @throws \Throwable
     */
    public function testDoNotAddClaimsToIdTokenRuleTest($responseType)
    {
        $this->resultBag->add(new Result(ResponseTypeRule::class, $responseType));

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        ) ??
        new Result(AddClaimsToIdTokenRule::class, null);

        $this->assertFalse($result->getValue());
    }

    public static function invalidResponseTypeProvider(): array
    {
        return [
            ['code'],
            ['token'],
            ['id_token token'],
            ['code id_token'],
            ['code token'],
            ['code id_token token'],
        ];
    }

    /**
     * A client configured with the administrator-only `add_claims_to_id_token` option gets the claims released
     * in the ID Token even for a response type that would not otherwise trigger it (e.g. `id_token token`).
     *
     * @throws \Throwable
     */
    public function testAddsClaimsWhenClientConfiguredEvenForNonIdTokenResponseType(): void
    {
        $this->resultBag->add(new Result(ResponseTypeRule::class, 'id_token token'));

        $clientStub = $this->createStub(ClientEntityInterface::class);
        $clientStub->method('getAddClaimsToIdToken')->willReturn(true);
        $this->resultBag->add(new Result(ClientRule::class, $clientStub));

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        ) ??
        new Result(AddClaimsToIdTokenRule::class, null);

        $this->assertTrue($result->getValue());
    }

    /**
     * When neither the response type nor the client requests it, claims are not released in the ID Token.
     *
     * @throws \Throwable
     */
    public function testDoesNotAddClaimsWhenNeitherResponseTypeNorClientRequestIt(): void
    {
        $this->resultBag->add(new Result(ResponseTypeRule::class, 'id_token token'));

        $clientStub = $this->createStub(ClientEntityInterface::class);
        $clientStub->method('getAddClaimsToIdToken')->willReturn(false);
        $this->resultBag->add(new Result(ClientRule::class, $clientStub));

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        ) ??
        new Result(AddClaimsToIdTokenRule::class, null);

        $this->assertFalse($result->getValue());
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testAddClaimsToIdTokenRuleThrowsWithNoResponseTypeParamTest()
    {
        $this->expectException(LogicException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }
}
