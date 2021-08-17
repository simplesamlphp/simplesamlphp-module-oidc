<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Result;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\ResultBag;

class AddClaimsToIdTokenRuleTest extends TestCase
{
    protected $requestStub;

    protected $requestParams = [
        'client_id' => 'client123',
        'response_type' => '',
    ];

    protected $sampleResponseTypes = [
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

    /**
     * @var ResultBag
     */
    private $resultBag;

    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);

        $this->resultBag = new ResultBag();
    }

    /**
     * @dataProvider validResponseTypeProvider
     */
    public function testAddClaimsToIdTokenRuleTest($responseType)
    {
        $rule = new AddClaimsToIdTokenRule();
        $this->resultBag->add(new Result(ResponseTypeRule::class, $responseType));

        $result = $rule->checkRule($this->requestStub, $this->resultBag) ??
            new Result(AddClaimsToIdTokenRule::class, null);
        $this->assertTrue($result->getValue());
    }

    public function validResponseTypeProvider(): array
    {
        return [
            ['id_token'],
        ];
    }

    /**
     * @dataProvider invalidResponseTypeProvider
     */
    public function testDoNotAddClaimsToIdTokenRuleTest($responseType)
    {
        $rule = new AddClaimsToIdTokenRule();
        $this->resultBag->add(new Result(ResponseTypeRule::class, $responseType));

        $result = $rule->checkRule($this->requestStub, $this->resultBag) ??
            new Result(AddClaimsToIdTokenRule::class, null);
        ;
        $this->assertFalse($result->getValue());
    }

    public function invalidResponseTypeProvider(): array
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

    public function testAddClaimsToIdTokenRuleThrowsWithNoResponseTypeParamTest()
    {
        $rule = new AddClaimsToIdTokenRule();
        $this->expectException(\LogicException::class);
        $rule->checkRule($this->requestStub, $this->resultBag);
    }
}
