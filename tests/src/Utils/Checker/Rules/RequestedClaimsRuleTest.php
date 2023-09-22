<?php

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\ResultBag;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use Throwable;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\RequestedClaimsRule
 */
class RequestedClaimsRuleTest extends TestCase
{
    protected ResultBag $resultBag;
    protected $clientStub;
    protected $request;
    protected string $redirectUri = 'https://some-redirect-uri.org';
    protected $loggerServiceStub;
    protected static string $userIdAttr = 'uid';


    protected function setUp(): void
    {
        $this->resultBag = new ResultBag();
        $this->clientStub = $this->createStub(ClientEntityInterface::class);
        $this->request = $this->createStub(ServerRequestInterface::class);
        $this->clientStub->method('getScopes')->willReturn(['openid', 'profile', 'email']);
        $this->resultBag->add(new Result(ClientIdRule::class, $this->clientStub));
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    /**
     * @throws Throwable
     */
    public function testNoRequestedClaims(): void
    {
        $rule = new RequestedClaimsRule(new ClaimTranslatorExtractor(self::$userIdAttr));
        $result = $rule->checkRule($this->request, $this->resultBag, $this->loggerServiceStub, []);
        $this->assertNull($result);
    }

    /**
     * @throws Throwable
     */
    public function testWithClaims(): void
    {
        $expectedClaims = [
            'userinfo' => [
                "name" => null,
                "email" => [
                    "essential" => true,
                    "extras_stuff_not_in_spec" => "should be ignored"
                ]
            ],
            "id_token" => [
                'name' => [
                    "essential" => true
                ]
            ],
            "additional_stuff" => [
                "should be ignored"
            ]
        ];
        $requestedClaims = $expectedClaims;
        // Add some claims the client is not authorized for
        $requestedClaims['userinfo']['someClaim'] = null;
        $requestedClaims['id_token']['secret_password'] = null;
        $this->request->method('getQueryParams')->willReturn([
            'claims' => json_encode($requestedClaims),
            'client_id' => 'abc'
                                                             ]);

        $rule = new RequestedClaimsRule(new ClaimTranslatorExtractor(self::$userIdAttr));
        $result = $rule->checkRule($this->request, $this->resultBag, $this->loggerServiceStub, []);
        $this->assertNotNull($result);
        $this->assertEquals($expectedClaims, $result->getValue());
    }


    /**
     * @throws Throwable
     */
    public function testOnlyWithNonStandardClaimRequest(): void
    {
        $expectedClaims = [
            "additional_stuff" => [
                "should be ignored"
            ]
        ];
        $requestedClaims = $expectedClaims;
        $this->request->method('getQueryParams')->willReturn([
                                                                 'claims' => json_encode($requestedClaims),
                                                                 'client_id' => 'abc'
                                                             ]);

        $rule = new RequestedClaimsRule(new ClaimTranslatorExtractor(self::$userIdAttr));
        $result = $rule->checkRule($this->request, $this->resultBag, $this->loggerServiceStub, []);
        $this->assertNotNull($result);
        $this->assertEquals($expectedClaims, $result->getValue());
    }
}
