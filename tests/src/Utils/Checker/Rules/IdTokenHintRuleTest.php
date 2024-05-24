<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Factories\CryptKeyFactory;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\IdTokenHintRule;
use Throwable;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\IdTokenHintRule
 */
class IdTokenHintRuleTest extends TestCase
{
    protected Stub $requestStub;
    protected Stub $resultBagStub;
    protected Stub $moduleConfigStub;
    protected Stub $cryptKeyFactoryStub;

    protected static string $certFolder;
    protected static string $privateKeyPath;
    protected static string $publicKeyPath;
    protected static CryptKey $privateKey;
    protected static CryptKey $publicKey;

    protected static string $issuer = 'https://example.org';
    private Configuration $jwtConfig;

    protected Stub $loggerServiceStub;

    public static function setUpBeforeClass(): void
    {
        self::$certFolder = dirname(__DIR__, 5) . '/docker/ssp/';
        self::$privateKeyPath = self::$certFolder . ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME;
        self::$publicKeyPath = self::$certFolder . ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME;
        self::$privateKey = new CryptKey(self::$privateKeyPath, null, false);
        self::$publicKey = new CryptKey(self::$publicKeyPath, null, false);
    }

    /**
     * @throws ReflectionException
     * @throws Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);

        $this->resultBagStub = $this->createStub(ResultBagInterface::class);

        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->moduleConfigStub->method('getProtocolSigner')->willReturn(new Sha256());
        $this->moduleConfigStub->method('getIssuer')->willReturn(self::$issuer);

        $this->cryptKeyFactoryStub = $this->createStub(CryptKeyFactory::class);
        $this->cryptKeyFactoryStub->method('buildPrivateKey')->willReturn(self::$privateKey);
        $this->cryptKeyFactoryStub->method('buildPublicKey')->willReturn(self::$publicKey);

        $this->jwtConfig = Configuration::forAsymmetricSigner(
            $this->moduleConfigStub->getProtocolSigner(),
            InMemory::plainText(self::$privateKey->getKeyContents()),
            InMemory::plainText(self::$publicKey->getKeyContents()),
        );

        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    public function testConstruct(): void
    {
        $this->assertInstanceOf(IdTokenHintRule::class, new IdTokenHintRule(
            $this->moduleConfigStub,
            $this->cryptKeyFactoryStub,
        ));
    }

    /**
     * @throws Throwable
     * @throws OidcServerException
     */
    public function testCheckRuleIsNullWhenParamNotSet(): void
    {
        $rule = new IdTokenHintRule($this->moduleConfigStub, $this->cryptKeyFactoryStub);
        $this->requestStub->method('getMethod')->willReturn('');
        $result = $rule->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        ) ?? new Result(IdTokenHintRule::class);

        $this->assertNull($result->getValue());
    }

    /**
     * @throws OidcServerException
     */
    public function testCheckRuleThrowsForMalformedIdToken(): void
    {
        $this->requestStub->method('getMethod')->willReturn('GET');
        $this->requestStub->method('getQueryParams')->willReturn(['id_token_hint' => 'malformed']);
        $rule = new IdTokenHintRule($this->moduleConfigStub, $this->cryptKeyFactoryStub);
        $this->expectException(Throwable::class);
        $rule->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);
    }

    /**
     * @throws OidcServerException
     */
    public function testCheckRuleThrowsForIdTokenWithInvalidSignature(): void
    {
        $this->requestStub->method('getMethod')->willReturn('GET');
        $invalidSignatureJwt = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUub3JnIiwic3ViIjo' .
        'iMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.JGJ_KSiXiRsgVc5nYFTSqbaeeM3UA5DGnOTaz3' .
        'UqbyHM0ogO3rq_-8FwLRzGk-7942U6rQ1ARziLsYYsUtH7yaUTWi6xSvh_mJQuF8hl_X3OghJWeXWms42OjAkHXtB-H7LQ_bEQNV' .
        'nF8XYLsq06MoHeHxAnDkVpVcZyDrmhauAqV1PTWsC9FMMKaxfoVsIbeQ0-PV_gAgzSK5-T0bliXPUdWFjvPXJ775jqqy4ZyNJYh' .
        '1_rZ1WyOrJu7AHkT9R4FNQNCw40BRzfI3S_OYBNirKAh5G0sctNwEEaJL_a3lEwKYSC-d_sZ6WBvFP8B138b7T6nPzI71tvfXE' .
        'Ru7Q7rA';

        $this->requestStub->method('getQueryParams')->willReturn(['id_token_hint' => $invalidSignatureJwt]);
        $rule = new IdTokenHintRule($this->moduleConfigStub, $this->cryptKeyFactoryStub);
        $this->expectException(Throwable::class);
        $rule->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);
    }

    /**
     * @throws ReflectionException
     * @throws OidcServerException
     */
    public function testCheckRuleThrowsForIdTokenWithInvalidIssuer(): void
    {
        $this->requestStub->method('getMethod')->willReturn('GET');

        $invalidIssuerJwt = $this->jwtConfig->builder()->issuedBy('invalid')->getToken(
            $this->moduleConfigStub->getProtocolSigner(),
            InMemory::plainText(self::$privateKey->getKeyContents()),
        )->toString();

        $this->requestStub->method('getQueryParams')->willReturn(['id_token_hint' => $invalidIssuerJwt]);
        $rule = new IdTokenHintRule($this->moduleConfigStub, $this->cryptKeyFactoryStub);
        $this->expectException(Throwable::class);
        $rule->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);
    }

    /**
     * @throws ReflectionException
     * @throws Throwable
     * @throws OidcServerException
     */
    public function testCheckRulePassesForValidIdToken(): void
    {
        $this->requestStub->method('getMethod')->willReturn('GET');

        $idToken = $this->jwtConfig->builder()->issuedBy(self::$issuer)->getToken(
            $this->moduleConfigStub->getProtocolSigner(),
            InMemory::plainText(self::$privateKey->getKeyContents()),
        )->toString();

        $this->requestStub->method('getQueryParams')->willReturn(['id_token_hint' => $idToken]);
        $rule = new IdTokenHintRule($this->moduleConfigStub, $this->cryptKeyFactoryStub);
        $result = $rule->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub) ??
        new Result(IdTokenHintRule::class);

        $this->assertInstanceOf(UnencryptedToken::class, $result->getValue());
    }
}
