<?php

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKey;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\PostLogoutRedirectUriRule;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\PostLogoutRedirectUriRule
 */
class PostLogoutRedirectUriRuleTest extends TestCase
{
    protected $clientRepository;
    protected $requestStub;
    protected $resultBagStub;
    protected $clientStub;

    protected static string $certFolder;
    protected static string $privateKeyPath;
    protected static string $publicKeyPath;
    protected static CryptKey $privateKey;
    protected static CryptKey $publicKey;

    protected static string $postLogoutRedirectUri = 'https://redirect.org/uri';
    protected static string $issuer = 'https://example.org';
    private Configuration $jwtConfig;

    public static function setUpBeforeClass(): void
    {
        self::$certFolder = dirname(__DIR__, 4) . '/docker/ssp/';
        self::$privateKeyPath = self::$certFolder . 'oidc_module.pem';
        self::$publicKeyPath = self::$certFolder . 'oidc_module.crt';
        self::$privateKey = new CryptKey(self::$privateKeyPath, null, false);
        self::$publicKey = new CryptKey(self::$publicKeyPath, null, false);
    }

    protected function setUp(): void
    {
        $this->clientRepository = $this->createStub(ClientRepository::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->requestStub->method('getMethod')->willReturn('GET');
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->clientStub = $this->createStub(ClientEntityInterface::class);

        $this->jwtConfig = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText(self::$privateKey->getKeyContents()),
            InMemory::plainText(self::$publicKey->getKeyContents())
        );
    }

    public function testCheckRuleReturnsNullIfNoParamSet(): void
    {
        $result = (new PostLogoutRedirectUriRule($this->clientRepository))
            ->checkRule($this->requestStub, $this->resultBagStub) ?? (new Result(PostLogoutRedirectUriRule::class));

        $this->assertNull($result->getValue());
    }

    public function testCheckRuleThrowsWhenIdTokenHintNotAvailable(): void
    {
        $this->requestStub->method('getQueryParams')
            ->willReturn(['post_logout_redirect_uri' => self::$postLogoutRedirectUri]);

        $this->expectException(\Throwable::class);

        (new PostLogoutRedirectUriRule($this->clientRepository))
            ->checkRule($this->requestStub, $this->resultBagStub) ?? (new Result(PostLogoutRedirectUriRule::class));
    }

    public function testCheckRuleThrowsWhenAudClaimNotValid(): void
    {
        $this->requestStub->method('getQueryParams')
            ->willReturn(['post_logout_redirect_uri' => self::$postLogoutRedirectUri]);

        $jwt = $this->jwtConfig->builder()->issuedBy(self::$issuer)
            ->getToken(
                new Sha256(),
                InMemory::plainText(self::$privateKey->getKeyContents())
            );


        $this->resultBagStub->method('getOrFail')->willReturnOnConsecutiveCalls(
            new Result(StateRule::class),
            new Result(IdTokenHintRule::class, $jwt)
        );

        $this->expectException(\Throwable::class);

        (new PostLogoutRedirectUriRule($this->clientRepository))
            ->checkRule($this->requestStub, $this->resultBagStub) ?? (new Result(PostLogoutRedirectUriRule::class));
    }

    public function testCheckRuleThrowsWhenClientNotFound(): void
    {
        $this->requestStub->method('getQueryParams')
            ->willReturn(['post_logout_redirect_uri' => self::$postLogoutRedirectUri]);

        $jwt = $this->jwtConfig->builder()
            ->issuedBy(self::$issuer)
            ->permittedFor('invalid-client-id')
            ->getToken(
                new Sha256(),
                InMemory::plainText(self::$privateKey->getKeyContents())
            );

        $this->clientRepository->method('findById')->willReturn(null);

        $this->resultBagStub->method('getOrFail')->willReturnOnConsecutiveCalls(
            new Result(StateRule::class),
            new Result(IdTokenHintRule::class, $jwt)
        );

        $this->expectException(\Throwable::class);

        (new PostLogoutRedirectUriRule($this->clientRepository))
            ->checkRule($this->requestStub, $this->resultBagStub) ?? (new Result(PostLogoutRedirectUriRule::class));
    }

    public function testCheckRuleThrowsWhenPostLogoutRegisteredUriNotRegistered(): void
    {
        $this->requestStub->method('getQueryParams')
            ->willReturn(['post_logout_redirect_uri' => self::$postLogoutRedirectUri]);

        $jwt = $this->jwtConfig->builder()
            ->issuedBy(self::$issuer)
            ->permittedFor('client-id')
            ->getToken(
                new Sha256(),
                InMemory::plainText(self::$privateKey->getKeyContents())
            );

        $this->clientStub->method('getPostLogoutRedirectUri')->willReturn([
            'https://some-other-uri'
                                                                          ]);

        $this->clientRepository->method('findById')->willReturn($this->clientStub);

        $this->resultBagStub->method('getOrFail')->willReturnOnConsecutiveCalls(
            new Result(StateRule::class),
            new Result(IdTokenHintRule::class, $jwt)
        );

        $this->expectException(\Throwable::class);

        (new PostLogoutRedirectUriRule($this->clientRepository))
            ->checkRule($this->requestStub, $this->resultBagStub) ?? (new Result(PostLogoutRedirectUriRule::class));
    }

    public function testCheckRuleReturnsForRegisteredPostLogoutRedirectUri(): void
    {
        $this->requestStub->method('getQueryParams')
            ->willReturn(['post_logout_redirect_uri' => self::$postLogoutRedirectUri]);

        $jwt = $this->jwtConfig->builder()
            ->issuedBy(self::$issuer)
            ->permittedFor('client-id')
            ->getToken(
                new Sha256(),
                InMemory::plainText(self::$privateKey->getKeyContents())
            );

        $this->clientStub->method('getPostLogoutRedirectUri')->willReturn([
            self::$postLogoutRedirectUri
                                                                          ]);

        $this->clientRepository->method('findById')->willReturn($this->clientStub);

        $this->resultBagStub->method('getOrFail')->willReturnOnConsecutiveCalls(
            new Result(StateRule::class),
            new Result(IdTokenHintRule::class, $jwt)
        );

        $result = (new PostLogoutRedirectUriRule($this->clientRepository))
            ->checkRule($this->requestStub, $this->resultBagStub) ?? (new Result(PostLogoutRedirectUriRule::class));

        $this->assertEquals(self::$postLogoutRedirectUri, $result->getValue());
    }
}
