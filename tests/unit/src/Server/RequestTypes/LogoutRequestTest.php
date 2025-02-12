<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestTypes;

use Lcobucci\JWT\UnencryptedToken;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\RequestTypes\LogoutRequest;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestTypes\LogoutRequest
 */
class LogoutRequestTest extends TestCase
{
    protected Stub $idTokenHintStub;

    protected static string $postLogoutRedirectUri = 'https://redirect.org/uri';
    protected static string $state = 'state123';
    protected static string $uiLocales = 'en';

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->idTokenHintStub = $this->createStub(UnencryptedToken::class);
    }

    public function testConstructWithoutParams(): void
    {
        $logoutRequest = new LogoutRequest();
        $this->assertInstanceOf(LogoutRequest::class, $logoutRequest);

        $this->assertNull($logoutRequest->getIdTokenHint());
        $this->assertNull($logoutRequest->getPostLogoutRedirectUri());
        $this->assertNull($logoutRequest->getState());
        $this->assertNull($logoutRequest->getUiLocales());
    }

    public function testConstructWithParams(): void
    {
        $logoutRequest = new LogoutRequest(
            $this->idTokenHintStub,
            self::$postLogoutRedirectUri,
            self::$state,
            self::$uiLocales,
        );

        $this->assertInstanceOf(LogoutRequest::class, $logoutRequest);

        $this->assertEquals($this->idTokenHintStub, $logoutRequest->getIdTokenHint());
        $this->assertEquals(self::$postLogoutRedirectUri, $logoutRequest->getPostLogoutRedirectUri());
        $this->assertEquals(self::$state, $logoutRequest->getState());
        $this->assertEquals(self::$uiLocales, $logoutRequest->getUiLocales());
    }

    public function testFluentPropertySetters(): void
    {
        $logoutRequest = (new LogoutRequest())
            ->setIdTokenHint($this->idTokenHintStub)
            ->setPostLogoutRedirectUri(self::$postLogoutRedirectUri)
            ->setState(self::$state)
            ->setUiLocales(self::$uiLocales);

        $this->assertInstanceOf(LogoutRequest::class, $logoutRequest);

        $this->assertEquals($this->idTokenHintStub, $logoutRequest->getIdTokenHint());
        $this->assertEquals(self::$postLogoutRedirectUri, $logoutRequest->getPostLogoutRedirectUri());
        $this->assertEquals(self::$state, $logoutRequest->getState());
        $this->assertEquals(self::$uiLocales, $logoutRequest->getUiLocales());
    }
}
