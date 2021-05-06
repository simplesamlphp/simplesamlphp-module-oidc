<?php

namespace spec\SimpleSAML\Modules\OpenIDConnect\Server\ResponseTypes;

use Laminas\Diactoros\ServerRequest;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKey;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Configuration;
use SimpleSAML\Error\Exception;
use SimpleSAML\Modules\OpenIDConnect\Entity\AccessTokenEntity;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Entity\ScopeEntity;
use SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity;
use SimpleSAML\Modules\OpenIDConnect\Factories\AuthSimpleFactory;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;
use SimpleSAML\Modules\OpenIDConnect\Server\ResponseTypes\IdTokenResponse;
use SimpleSAML\Modules\OpenIDConnect\Services\AuthenticationService;
use SimpleSAML\Modules\OpenIDConnect\Services\AuthProcService;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;
use SimpleSAML\Modules\OpenIDConnect\Services\OidcOpenIdProviderMetadataService;

class IdTokenResponseSpec extends ObjectBehavior
{

    /**
     * @var ClaimExtractor
     */
    private $claimExtractor;

    public function let(
        IdentityProviderInterface $identityProvider,
        ConfigurationService $configurationService,
        AccessTokenEntity $accessToken,
        ClientEntity $clientEntity
    ): void {
        $certFolder = dirname(__DIR__, 3) . '/docker/ssp/';
//        Configuration::setPreLoadedConfig(
//            Configuration::loadFromArray([
//                'example' => 'key',
//                'certdir' => $certFolder,
//            ])
//        );
        $claimExtractor = new ClaimExtractor();
        $userId = 'theUserId';
        $userEntity = UserEntity::fromData($userId, []);
        $scopes = [
            ScopeEntity::fromData('openid'),
        ];
        $expiration = (new \DateTimeImmutable())->setTimestamp(time() + 3600);
        $accessToken->getExpiryDateTime()->willReturn($expiration);
        $accessToken->__toString()->willReturn('AccessToken123');
        $accessToken->getIdentifier()->willReturn('tokenId');
        $accessToken->getScopes()->willReturn($scopes);
        $accessToken->getUserIdentifier()->willReturn($userId);
        $identityProvider->getUserEntityByIdentifier($userId)->willReturn($userEntity);
        $configurationService->getSigner()->willReturn(new Sha256());
        $configurationService->getSimpleSAMLSelfURLHost()->willReturn('https://myissuer');
        $configurationService->getKeyId()->willReturn('myKeyId');

        $clientEntity->getIdentifier()->willReturn('clientId');
        $accessToken->getClient()->willReturn($clientEntity);
        $this->beConstructedWith(
            $identityProvider,
            $claimExtractor,
            $configurationService
        );
        $cryptKey = new CryptKey($certFolder . '/oidc_module.pem', '', false);
        $this->setPrivateKey($cryptKey);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(IdTokenResponse::class);
    }

    public function it_can_generate_response(AccessTokenEntity $accessToken )
    {
        //TODO: is there a response type that lets me capture what is written
        $response = new \Laminas\Diactoros\Response();
        $this->setAccessToken($accessToken);
        $this->generateHttpResponse($response);

        //TODO: how to get the response contents and assert them
        $body = $response->getBody()->getContents();
        var_dump($body);
        //TODO: assert that nbf and iat are integers. Viewing the jwt from var_dump indicates they are float
    }

}