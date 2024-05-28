<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Forms;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Forms\ClientForm;
use SimpleSAML\Module\oidc\Forms\Controls\CsrfProtection;
use SimpleSAML\Module\oidc\ModuleConfig;

/**
 * @covers \SimpleSAML\Module\oidc\Forms\ClientForm
 */
class ClientFormTest extends TestCase
{
    /** @var \PHPUnit\Framework\MockObject\MockObject */
    protected MockObject $csrfProtection;

    /** @var \PHPUnit\Framework\MockObject\MockObject */
    protected MockObject $moduleConfig;

    /** @var \PHPUnit\Framework\MockObject\MockObject  */
    protected MockObject $serverRequestMock;

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        parent::setUp();
        Configuration::clearInternalState();
        $this->csrfProtection =  $this->createMock(CsrfProtection::class);
        $this->moduleConfig = $this->createMock(ModuleConfig::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
    }

    public static function setUpBeforeClass(): void
    {
        // To make lib/SimpleSAML/Utils/HTTP::getSelfURL() work...
        global $_SERVER;
        $_SERVER['REQUEST_URI'] = '/';
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
        $clientForm = $this->prepareMockedInstance();
        $clientForm->setValues(['allowed_origin' => $url]);
        $clientForm->validateAllowedOrigin($clientForm);

        $this->assertEquals(!$isValid, $clientForm->hasErrors(), $url);
    }

    /**
     * @return \SimpleSAML\Module\oidc\Forms\ClientForm
     * @throws \Exception
     */
    protected function prepareMockedInstance(): ClientForm
    {
        return new ClientForm($this->moduleConfig, $this->csrfProtection);
    }
}
