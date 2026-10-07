<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\ClaimSetEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestedClaimsRule
 */
#[AllowMockObjectsWithoutExpectations]
class RequestedClaimsRuleTest extends TestCase
{
    protected ResultBag $resultBag;

    protected Stub $clientStub;

    protected Stub $requestStub;

    protected string $redirectUri = 'https://some-redirect-uri.org';

    protected Stub $loggerServiceStub;

    /** @var string[] */
    protected static array $userIdAttrs = ['uid'];

    protected Stub $requestParamsResolverStub;

    protected Stub $claimSetEntityFactoryStub;

    protected Helpers $helpers;

    protected Stub $responseModeStub;

    protected ?string $scopeParam = 'openid profile';


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->resultBag = new ResultBag();
        $this->clientStub = $this->createStub(ClientEntityInterface::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->clientStub->method('getScopes')->willReturn(['openid', 'profile', 'email']);
        $this->resultBag->add(new Result(ClientRule::class, $this->clientStub));
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')
            ->willReturnCallback(fn(string $param): ?string => $param === 'scope' ? $this->scopeParam : null);
        $this->claimSetEntityFactoryStub = $this->createStub(ClaimSetEntityFactory::class);
        $this->claimSetEntityFactoryStub->method('build')
            ->willReturnCallback(function (string $scope, array $claims) {
                $claimSetEntityStub = $this->createStub(ClaimSetEntity::class);
                $claimSetEntityStub->method('getScope')->willReturn($scope);
                $claimSetEntityStub->method('getClaims')->willReturn($claims);
                return $claimSetEntityStub;
            });

        $this->helpers = new Helpers();
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
    }


    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
        ?ClaimTranslatorExtractor $claimTranslatorExtractor = null,
    ): RequestedClaimsRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;
        $claimTranslatorExtractor ??= new ClaimTranslatorExtractor(
            self::$userIdAttrs,
            $this->claimSetEntityFactoryStub,
        );

        return new RequestedClaimsRule(
            $requestParamsResolver,
            $helpers,
            $claimTranslatorExtractor,
        );
    }


    /**
     * @throws \Throwable
     */
    public function testNoRequestedClaims(): void
    {
        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
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

        $this->requestParamsResolverStub->method('getBasedOnAllowedMethods')->willReturn(json_encode($requestedClaims));

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
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
        $this->requestParamsResolverStub->method('getBasedOnAllowedMethods')->willReturn(json_encode($requestedClaims));

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
        $this->assertNotNull($result);
        $this->assertEquals($expectedClaims, $result->getValue());
    }


    /**
     * A plain OAuth 2.0 request, which asks for neither the openid scope nor a credential, gets neither an ID
     * token nor a UserInfo response, so its claims parameter is ignored: an essential acr in it is not demanded
     * of the login (AcrValuesRule reads this rule's result).
     *
     * @throws \Throwable
     */
    public function testIgnoresTheClaimsOfAPlainOAuth2Request(): void
    {
        $this->scopeParam = 'profile';
        $this->requestParamsResolverStub->method('getBasedOnAllowedMethods')->willReturn(json_encode([
            'id_token' => ['acr' => ['essential' => true, 'value' => 'urn:example:unavailable']],
            'userinfo' => ['email' => null],
        ]));
        $this->requestParamsResolverStub->method('isVciAuthorizationCodeRequest')->willReturn(false);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertNull($result);
    }


    /**
     * An OpenID4VCI request need not carry the openid scope, and its claims are kept as before.
     *
     * @throws \Throwable
     */
    public function testKeepsTheClaimsOfACredentialRequestWithoutTheOpenIdScope(): void
    {
        $this->scopeParam = 'ResearchCredential';
        $requestedClaims = ['userinfo' => ['email' => null]];
        $this->requestParamsResolverStub->method('getBasedOnAllowedMethods')->willReturn(json_encode($requestedClaims));
        $this->requestParamsResolverStub->method('isVciAuthorizationCodeRequest')->willReturn(true);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertNotNull($result);
        $this->assertEquals($requestedClaims, $result->getValue());
    }
}
