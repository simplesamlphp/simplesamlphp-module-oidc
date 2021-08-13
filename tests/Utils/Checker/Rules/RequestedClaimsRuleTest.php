<?php


namespace Tests\SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;


use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\ClaimTranslatorExtractor;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\ResultBag;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\RequestedClaimsRule;

class RequestedClaimsRuleTest extends TestCase
{

    protected $resultBag;
    protected $clientStub;
    protected $request;
    protected $redirectUri = 'https://some-redirect-uri.org';
    protected $clientRepository;


    protected function setUp(): void
    {
        $this->resultBag = new ResultBag();
        $this->clientStub = $this->createStub(ClientEntityInterface::class);
        $this->request = $this->createStub(ServerRequestInterface::class);
        $this->clientRepository = $this->createStub(ClientRepositoryInterface::class);
        $this->clientRepository->method('getClientEntity')->willReturn($this->clientStub);
        $this->clientStub->method('getScopes')->willReturn(['openid', 'profile', 'email']);
    }

    public function testNoRequestedClaims(): void
    {
        $rule = new RequestedClaimsRule($this->clientRepository, new ClaimTranslatorExtractor());
        $resultBag = new ResultBag();
        $result = $rule->checkRule($this->request, $resultBag, []);
        $this->assertNull($result);
    }

    public function testWithClaims(): void
    {
        $expectedClaims = [
            'userinfo'=> [
                "name" => null,
                "email" => [
                    "essential"=> true,
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
        $this->request->method('getQueryParams')->willReturn([
            'claims' => json_encode($expectedClaims),
            'client_id' => 'abc'
                                                             ]);

        $rule = new RequestedClaimsRule($this->clientRepository, new ClaimTranslatorExtractor());
        $resultBag = new ResultBag();
        $result = $rule->checkRule($this->request, $resultBag, []);
        $this->assertEquals($expectedClaims, $result->getValue());
    }
}