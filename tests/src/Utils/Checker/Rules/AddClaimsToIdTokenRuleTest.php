<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\Stub;
use LogicException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\ResultBag;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\AddClaimsToIdTokenRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ResponseTypeRule;
use Throwable;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\AddClaimsToIdTokenRule
 */
class AddClaimsToIdTokenRuleTest extends TestCase
{
    protected Stub $requestStub;

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

    /**
     * @throws Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);

        $this->resultBag = new ResultBag();
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    /**
     * @dataProvider validResponseTypeProvider
     * @throws Throwable
     */
    public function testAddClaimsToIdTokenRuleTest($responseType)
    {
        $rule = new AddClaimsToIdTokenRule();
        $this->resultBag->add(new Result(ResponseTypeRule::class, $responseType));

        $result = $rule->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub) ??
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
     * @throws Throwable
     */
    public function testDoNotAddClaimsToIdTokenRuleTest($responseType)
    {
        $rule = new AddClaimsToIdTokenRule();
        $this->resultBag->add(new Result(ResponseTypeRule::class, $responseType));

        $result = $rule->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub) ??
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
     * @throws Throwable
     * @throws OidcServerException
     */
    public function testAddClaimsToIdTokenRuleThrowsWithNoResponseTypeParamTest()
    {
        $rule = new AddClaimsToIdTokenRule();
        $this->expectException(LogicException::class);
        $rule->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub);
    }
}
