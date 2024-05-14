<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Forms;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Forms\ClientForm;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Session;

/**
 * @covers \SimpleSAML\Module\oidc\Forms\ClientForm
 */
class ClientFormTest extends TestCase
{

    /** @var \SimpleSAML\Session */
    protected Session $session;
    /**
     */
    public function setUp(): void
    {
        parent::setUp();

        // The REQUEST_URI is required to create the session
        $_SERVER['REQUEST_URI'] = '/dummy';
        $this->session = Session::getSessionFromRequest();
    }

    public static function validateOriginProvider(): array
    {
        return [
            ['https://example.com', true],
            ['https://example.com.', true],
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
            ['http://*.example.com', true],
            ['http://*.example.com.', true],
            ['https://foo.example.com:80', true],
            ['http://*.example', false],
            ['http://foo.*.test.com', false],
            ['http://*', false],
            ['http://*.com', false],
            ['https://test........', false],
            ['https://developer.mozilla.org:80', true],
            ['http://attacker.bar/test.php', false],
            ['https://cors-test.codehappy.dev', true],
            ['https://cors-test.codehappy.dev:8080', true],
        ];
    }


    /**
     * @dataProvider validateOriginProvider
     * @param string $value
     * @return void
     */
    public function testValidateOrigin(string $value, bool $isValid): void
    {
        $clientForm = new ClientForm(new ModuleConfig(), $this->session);
        $clientForm->setValues(['allowed_origin' => $value]);
        $clientForm->validateAllowedOrigin($clientForm);

        $this->assertEquals(!$isValid, $clientForm->hasErrors(), $value);
    }
}
