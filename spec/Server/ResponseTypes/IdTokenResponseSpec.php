<?php

namespace spec\SimpleSAML\Modules\OpenIDConnect\Server\ResponseTypes;

use DateTimeImmutable;
use Laminas\Diactoros\Response;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token as TokenInterface;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Server\CryptKey;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use PhpSpec\Exception\Example\FailureException;
use PhpSpec\ObjectBehavior;
use SimpleSAML\Configuration;
use SimpleSAML\Modules\OpenIDConnect\Entity\AccessTokenEntity;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Entity\ScopeEntity;
use SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity;
use SimpleSAML\Modules\OpenIDConnect\Server\ResponseTypes\IdTokenResponse;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;

class IdTokenResponseSpec extends ObjectBehavior
{

    public const TOKEN_ID = 'tokenId';
    public const ISSUER = 'someIssuer';
    public const CLIENT_ID = 'clientId';
    public const SUBJECT = 'userId';
    public const KEY_ID = 'f0687e30bc113bef19f5ec6762f902e0';

    private $certFolder;

    public function let(
        IdentityProviderInterface $identityProvider,
        ConfigurationService $configurationService,
        AccessTokenEntity $accessToken,
        ClientEntity $clientEntity,
        Configuration $oidcConfig
    ): void {
        $this->certFolder = dirname(__DIR__, 3) . '/docker/ssp/';
        $claimExtractor = new ClaimExtractor();
        $userEntity = UserEntity::fromData(self::SUBJECT, [
            'email' => 'myEmail@example.com'
        ]);
        $scopes = [
            ScopeEntity::fromData('openid'),
            ScopeEntity::fromData('email'),
        ];
        $expiration = (new \DateTimeImmutable())->setTimestamp(time() + 3600);
        $accessToken->getExpiryDateTime()->willReturn($expiration);
        $accessToken->__toString()->willReturn('AccessToken123');
        $accessToken->getIdentifier()->willReturn(self::TOKEN_ID);
        $accessToken->getScopes()->willReturn($scopes);
        $accessToken->getUserIdentifier()->willReturn(self::SUBJECT);
        $identityProvider->getUserEntityByIdentifier(self::SUBJECT)->willReturn($userEntity);
        $configurationService->getSigner()->willReturn(new Sha256());
        $configurationService->getSimpleSAMLSelfURLHost()->willReturn(self::ISSUER);
        $configurationService->getCertPath()->willReturn($this->certFolder . '/oidc_module.crt');
        $configurationService->getOpenIDConnectConfiguration()->willReturn($oidcConfig);

        $clientEntity->getIdentifier()->willReturn(self::CLIENT_ID);
        $accessToken->getClient()->willReturn($clientEntity);
        $this->beConstructedWith(
            $identityProvider,
            $claimExtractor,
            $configurationService
        );
        $cryptKey = new CryptKey($this->certFolder . '/oidc_module.pem', '', false);
        $this->setPrivateKey($cryptKey);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(IdTokenResponse::class);
    }

    public function it_can_generate_response(AccessTokenEntity $accessToken, Configuration $oidcConfig)
    {
        $oidcConfig->getBoolean('alwaysAddClaimsToIdToken', true)->willReturn(true);
        $response = new Response();
        $this->setAccessToken($accessToken);
        $response = $this->generateHttpResponse($response);

        $response->getBody()->rewind();
        $body = $response->getBody()->getContents();
        echo "json body response " . $body->getWrappedObject();
        $body->shouldHaveValidIdToken(['email' => 'myEmail@example.com']);
    }

    public function it_can_generate_response_with_no_token_claims(AccessTokenEntity $accessToken, Configuration $oidcConfig)
    {
        $oidcConfig->getBoolean('alwaysAddClaimsToIdToken', true)->willReturn(false);
        $response = new Response();
        $this->setAccessToken($accessToken);
        $response = $this->generateHttpResponse($response);

        $response->getBody()->rewind();
        $body = $response->getBody()->getContents();
        echo "json body response " . $body->getWrappedObject();
        $body->shouldHaveValidIdToken();
    }

    public function getMatchers(): array
    {
        return [
            'haveValidIdToken' => function ($subject, $expectedClaims = []) {
                // Check response format
                $result = json_decode($subject, true);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    throw new FailureException('Response not json ' . json_last_error_msg());
                }
                $expectedResponseFields = ['id_token', 'expires_in', 'token_type', 'access_token'];
                $responseKeys = array_intersect_key(array_flip($expectedResponseFields), $result);
                if ($responseKeys !== array_flip($expectedResponseFields)) {
                    throw new FailureException(
                        'missing expected keys. Got ' . var_export(array_keys($result), true)
                        . ' need ' . var_export($expectedResponseFields, true)
                    );
                }
                // Check ID token
                $validator = new Validator();
                /** @var TokenInterface\Plain $token */
                $token = (new Parser(new JoseEncoder()))->parse($result['id_token']);
                $validator->assert(
                    $token,
                    new IdentifiedBy(self::TOKEN_ID),
                    new IssuedBy(self::ISSUER),
                    new PermittedFor(self::CLIENT_ID),
                    new RelatedTo(self::SUBJECT),
                    new StrictValidAt(SystemClock::fromUTC()),
                    new SignedWith(
                        new Sha256(),
                        InMemory::plainText(file_get_contents($this->certFolder . '/oidc_module.crt'))
                    )
                );

                if ($token->headers()->get('kid') !== self::KEY_ID) {
                    throw new FailureException(
                        'Wrong key id. Expected ' . self::KEY_ID . ' was ' . $token->headers()->get('kid')
                    );
                }
                $expectedClaimsKeys = array_keys($expectedClaims);
                $expectedClaimsKeys = array_merge(['iss', 'aud', 'jti', 'nbf', 'exp', 'sub', 'iat'], $expectedClaimsKeys);
                $claims = array_keys($token->claims()->all());
                if ($claims !== $expectedClaimsKeys) {
                    throw new FailureException(
                        'missing expected claim. Got ' . var_export($claims, true)
                        . ' need ' . var_export($expectedClaimsKeys, true)
                    );
                }
                foreach ($expectedClaims as $claim => $value) {
                    $valFromToken = $token->claims()->get($claim);
                    if ($value !== $valFromToken) {
                        throw new FailureException(
                            'Expected claim value ' . var_export($value, true)
                            . ' got ' . var_export($valFromToken, true)
                        );
                    }
                }

                $dateWithNoMicroseconds = ['nbf', 'exp', 'iat'];
                foreach ($dateWithNoMicroseconds as $key) {
                    /**
                     * @var DateTimeImmutable
                     */
                    $val = $token->claims()->get($key);
                    //Get format representing microseconds
                    $val = $val->format('u');
                    if ($val !== '000000') {
                        throw new FailureException("Value for '$key' has microseconds. micros '$val'");
                    }
                }
                return true;
            },
        ];
    }
}
