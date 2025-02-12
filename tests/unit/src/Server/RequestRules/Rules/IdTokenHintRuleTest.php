<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Factories\CryptKeyFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use Throwable;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule
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
    protected Stub $requestParamsResolverStub;
    protected Helpers $helpers;

    public static function setUpBeforeClass(): void
    {
        self::$certFolder = dirname(__DIR__, 6) . '/docker/ssp/';
        self::$privateKeyPath = self::$certFolder . ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME;
        self::$publicKeyPath = self::$certFolder . ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME;
        self::$privateKey = new CryptKey(self::$privateKeyPath, null, false);
        self::$publicKey = new CryptKey(self::$publicKeyPath, null, false);
    }

    /**
     * @throws \ReflectionException
     * @throws \Exception
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
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);

        $this->helpers = new Helpers();
    }

    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
        ?ModuleConfig $moduleConfig = null,
        ?CryptKeyFactory $cryptKeyFactory = null,
    ): IdTokenHintRule {

        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;
        $moduleConfig ??= $this->moduleConfigStub;
        $cryptKeyFactory ??= $this->cryptKeyFactoryStub;

        return new IdTokenHintRule(
            $requestParamsResolver,
            $helpers,
            $moduleConfig,
            $cryptKeyFactory,
        );
    }

    public function testConstruct(): void
    {
        $this->assertInstanceOf(IdTokenHintRule::class, $this->sut());
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleIsNullWhenParamNotSet(): void
    {
        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
        ) ?? new Result(IdTokenHintRule::class);

        $this->assertNull($result->getValue());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleThrowsForMalformedIdToken(): void
    {
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('malformed');
        $this->expectException(Throwable::class);
        $this->sut()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleThrowsForIdTokenWithInvalidSignature(): void
    {
        $invalidSignatureJwt = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUub3JnIiwic3ViIjo' .
        'iMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.JGJ_KSiXiRsgVc5nYFTSqbaeeM3UA5DGnOTaz3' .
        'UqbyHM0ogO3rq_-8FwLRzGk-7942U6rQ1ARziLsYYsUtH7yaUTWi6xSvh_mJQuF8hl_X3OghJWeXWms42OjAkHXtB-H7LQ_bEQNV' .
        'nF8XYLsq06MoHeHxAnDkVpVcZyDrmhauAqV1PTWsC9FMMKaxfoVsIbeQ0-PV_gAgzSK5-T0bliXPUdWFjvPXJ775jqqy4ZyNJYh' .
        '1_rZ1WyOrJu7AHkT9R4FNQNCw40BRzfI3S_OYBNirKAh5G0sctNwEEaJL_a3lEwKYSC-d_sZ6WBvFP8B138b7T6nPzI71tvfXE' .
        'Ru7Q7rA';

        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn($invalidSignatureJwt);
        $this->expectException(Throwable::class);
        $this->sut()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);
    }

    /**
     * @throws \ReflectionException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleThrowsForIdTokenWithInvalidIssuer(): void
    {
        $this->requestStub->method('getMethod')->willReturn('GET');

        $invalidIssuerJwt = $this->jwtConfig->builder()->issuedBy('invalid')->getToken(
            $this->moduleConfigStub->getProtocolSigner(),
            InMemory::plainText(self::$privateKey->getKeyContents()),
        )->toString();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn($invalidIssuerJwt);
        $this->expectException(Throwable::class);
        $this->sut()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub);
    }

    /**
     * @throws \ReflectionException
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRulePassesForValidIdToken(): void
    {
        $idToken = $this->jwtConfig->builder()->issuedBy(self::$issuer)->getToken(
            $this->moduleConfigStub->getProtocolSigner(),
            InMemory::plainText(self::$privateKey->getKeyContents()),
        )->toString();

        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn($idToken);
        $result = $this->sut()->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub) ??
        new Result(IdTokenHintRule::class);

        $this->assertInstanceOf(UnencryptedToken::class, $result->getValue());
    }
}
