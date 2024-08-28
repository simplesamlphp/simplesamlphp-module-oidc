<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\RequestRules\Rules;

use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\ParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestedClaimsRule
 */
class RequestedClaimsRuleTest extends TestCase
{
    protected ResultBag $resultBag;
    protected Stub $clientStub;
    protected Stub $requestStub;
    protected string $redirectUri = 'https://some-redirect-uri.org';
    protected Stub $loggerServiceStub;
    protected static string $userIdAttr = 'uid';
    protected Stub $paramsResolverStub;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->resultBag = new ResultBag();
        $this->clientStub = $this->createStub(ClientEntityInterface::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->clientStub->method('getScopes')->willReturn(['openid', 'profile', 'email']);
        $this->resultBag->add(new Result(ClientIdRule::class, $this->clientStub));
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->paramsResolverStub = $this->createStub(ParamsResolver::class);
    }

    protected function mock(): RequestedClaimsRule
    {
        return new RequestedClaimsRule(
            $this->paramsResolverStub,
            new ClaimTranslatorExtractor(self::$userIdAttr),
        );
    }

    /**
     * @throws \Throwable
     */
    public function testNoRequestedClaims(): void
    {
        $result = $this->mock()->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub);
        $this->assertNull($result);
    }

    /**
     * @throws \Throwable
     */
    public function testWithClaims(): void
    {
        $expectedClaims = [
            'userinfo' => [
                "name" => null,
                "email" => [
                    "essential" => true,
                    "extras_stuff_not_in_spec" => "should be ignored",
                ],
            ],
            "id_token" => [
                'name' => [
                    "essential" => true,
                ],
            ],
            "additional_stuff" => [
                "should be ignored",
            ],
        ];
        $requestedClaims = $expectedClaims;
        // Add some claims the client is not authorized for
        $requestedClaims['userinfo']['someClaim'] = null;
        $requestedClaims['id_token']['secret_password'] = null;

        $this->paramsResolverStub->method('getBasedOnAllowedMethods')->willReturn(json_encode($requestedClaims));

        $result = $this->mock()->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub);
        $this->assertNotNull($result);
        $this->assertEquals($expectedClaims, $result->getValue());
    }


    /**
     * @throws \Throwable
     */
    public function testOnlyWithNonStandardClaimRequest(): void
    {
        $expectedClaims = [
            "additional_stuff" => [
                "should be ignored",
            ],
        ];
        $requestedClaims = $expectedClaims;
        $this->paramsResolverStub->method('getBasedOnAllowedMethods')->willReturn(json_encode($requestedClaims));

        $result = $this->mock()->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub);
        $this->assertNotNull($result);
        $this->assertEquals($expectedClaims, $result->getValue());
    }
}
