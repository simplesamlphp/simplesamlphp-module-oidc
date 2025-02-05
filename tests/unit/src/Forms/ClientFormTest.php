<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Forms;

use DateTimeImmutable;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Forms\ClientForm;
use SimpleSAML\Module\oidc\Forms\Controls\CsrfProtection;
use SimpleSAML\Module\oidc\ModuleConfig;

/**
 * @covers \SimpleSAML\Module\oidc\Forms\ClientForm
 */
class ClientFormTest extends TestCase
{
    protected MockObject $csrfProtectionMock;

    protected MockObject $moduleConfigMock;

    protected MockObject $serverRequestMock;
    protected MockObject $sspBridgeMock;
    protected MockObject $sspBridgeAuthMock;
    protected MockObject $sspBridgeAuthSourceMock;

    protected array $clientDataSample;

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        parent::setUp();
        $this->csrfProtectionMock =  $this->createMock(CsrfProtection::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->sspBridgeMock = $this->createMock(SspBridge::class);

        $this->sspBridgeAuthMock = $this->createMock(SspBridge\Auth::class);
        $this->sspBridgeMock->method('auth')->willReturn($this->sspBridgeAuthMock);

        $this->sspBridgeAuthSourceMock = $this->createMock(SspBridge\Auth\Source::class);
        $this->sspBridgeAuthMock->method('source')->willReturn($this->sspBridgeAuthSourceMock);

        $this->clientDataSample = [
            'id' => 'clientId',
            'secret' => 'clientSecret',
            'name' => 'Test',
            'description' => 'Test',
            'auth_source' => 'default-sp',
            'redirect_uri' => [0 => 'https://example.com/redirect',],
            'scopes' => [0 => 'openid', 1 => 'offline_access', 2 => 'profile',],
            'is_enabled' => false,
            'is_confidential' => true,
            'owner' => null,
            'post_logout_redirect_uri' => [0 => 'https://example.com/',],
            'backchannel_logout_uri' => 'https://example.com/logout',
            'entity_identifier' => 'https://example.com/',
            'client_registration_types' => [0 => 'automatic',],
            'federation_jwks' => ['keys' => [0 => [],],],
            'jwks' => ['keys' => [0 => [],],],
            'jwks_uri' => 'https://example.com/jwks',
            'signed_jwks_uri' => 'https://example.com/signed-jwks',
            'registration_type' => RegistrationTypeEnum::Manual,
            'updated_at' => DateTimeImmutable::__set_state(
                ['date' => '2025-02-05 15:05:27.000000', 'timezone_type' => 3, 'timezone' => 'UTC',],
            ),
            'created_at' => DateTimeImmutable::__set_state(
                ['date' => '2024-12-01 11:54:12.000000', 'timezone_type' => 3, 'timezone' => 'UTC',],
            ),
            'expires_at' => null,
            'is_federated' => false,
            'allowed_origin' => [],
        ];
    }

    public static function setUpBeforeClass(): void
    {
        // To make lib/SimpleSAML/Utils/HTTP::getSelfURL() work...
        global $_SERVER;
        $_SERVER['REQUEST_URI'] = '/';
    }

    protected function sut(
        ?ModuleConfig $moduleConfig = null,
        ?CsrfProtection $csrfProtection = null,
        ?SspBridge $sspBridge = null,
    ): ClientForm {
        $moduleConfig ??= $this->moduleConfigMock;
        $csrfProtection ??= $this->csrfProtectionMock;
        $sspBridge ??= $this->sspBridgeMock;

        return new ClientForm(
            $moduleConfig,
            $csrfProtection,
            $sspBridge,
        );
    }

    public static function validateOriginProvider(): array
    {
        return [
            ['example.com', false],
            ['https://example.com.', true],
            ['http://example.com.', true],
            ['http://foo.', true],
            ['http://foo', true],
            ['https://user:pass@example.com', false],
            ['http://example.com', true],
            ['https://example.com:2020', true],
            ['https://localhost:2020', true],
            ['http://localhost:2020', true],
            ['http://localhost', true],
            ['https://example.com/path', false],
            ['https://example.com:8080/path', false],
            ['http://*.example.com', false],
            ['http://*.example.com.', false],
            ['https://foo.example.com:80', true],
            ['http://*.example', false],
            ['http://foo.*.test.com', false],
            ['http://*', false],
            ['http://*.com', false],
            ['https://test........', false],
            ['https://developer.mozilla.org:80', true],
            ['http://attacker.bar/test.php', false],
            ['https://cors-test.codehappy.dev', true],
            ['http://80.345.28.123', true],
            ['https://127.0.0.1:8080', true],
            ['https://127.0.0.1:8080/path', false],
            ['https://user:pass@127.0.0.1:8080/path', false],
        ];
    }

    /**
     * @param   string  $url
     * @param   bool    $isValid
     *
     * @return void
     * @throws \Exception
     */
    #[DataProvider('validateOriginProvider')]
    #[TestDox('Allowed Origin URL: $url is expected to be $isValid')]
    public function testValidateOrigin(string $url, bool $isValid): void
    {
        $clientForm = $this->sut();
        $clientForm->setValues(['allowed_origin' => $url]);
        $clientForm->validateAllowedOrigin($clientForm);

        $this->assertEquals(!$isValid, $clientForm->hasErrors(), $url);
    }

    public function testSetDefaultsLeavesValidAuthSourceValue(): void
    {
        $this->sspBridgeAuthSourceMock->method('getSources')->willReturn(['default-sp']);

        $sut = $this->sut()->setDefaults($this->clientDataSample);

        $this->assertSame('default-sp', $sut->getValues()['auth_source']);
    }

    public function testSetDefaultsUnsetsAuthSourceIfNotValid(): void
    {
        $sut = $this->sut()->setDefaults($this->clientDataSample);

        $this->assertNull($sut->getValues()['auth_source']);
    }
}
