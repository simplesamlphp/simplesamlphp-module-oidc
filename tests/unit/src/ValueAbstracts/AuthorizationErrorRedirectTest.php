<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\ValueAbstracts;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ValueAbstracts\AuthorizationErrorRedirect;
use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;

/**
 * Where an authorization error response goes, kept in the authentication state while the End-User authenticates.
 */
#[CoversClass(AuthorizationErrorRedirect::class)]
class AuthorizationErrorRedirectTest extends TestCase
{
    private const string REDIRECT_URI = 'https://rp.example.org/cb?dummy1=a';

    private const string PUSHED_REQUEST_URI = 'urn:ietf:params:oauth:request_uri:pushed-request';


    public function testItCarriesTheRedirectUriTheStateAndTheResponseMode(): void
    {
        $sut = new AuthorizationErrorRedirect(
            self::REDIRECT_URI,
            'the-state',
            ResponseModesEnum::FormPost,
            self::PUSHED_REQUEST_URI,
        );

        $this->assertSame(self::REDIRECT_URI, $sut->getRedirectUri());
        $this->assertSame('the-state', $sut->getState());
        $this->assertSame(ResponseModesEnum::FormPost, $sut->getResponseMode());
        $this->assertSame(self::PUSHED_REQUEST_URI, $sut->getPushedAuthorizationRequestUri());
    }


    public function testARequestWithoutStateOrResponseModeHasNone(): void
    {
        $sut = new AuthorizationErrorRedirect(self::REDIRECT_URI);

        $this->assertNull($sut->getState());
        $this->assertNull($sut->getResponseMode());
        $this->assertNull($sut->getPushedAuthorizationRequestUri());
    }


    /**
     * SimpleSAMLphp keeps the state in the session, serialized, across the End-User's round trip through the login.
     */
    public function testItSurvivesTheSessionSerialization(): void
    {
        $sut = new AuthorizationErrorRedirect(
            self::REDIRECT_URI,
            'the-state',
            ResponseModesEnum::FormPost,
            self::PUSHED_REQUEST_URI,
        );

        $restored = unserialize(serialize($sut));

        $this->assertInstanceOf(AuthorizationErrorRedirect::class, $restored);
        $this->assertSame(self::REDIRECT_URI, $restored->getRedirectUri());
        $this->assertSame('the-state', $restored->getState());
        $this->assertSame(ResponseModesEnum::FormPost, $restored->getResponseMode());
        $this->assertSame(self::PUSHED_REQUEST_URI, $restored->getPushedAuthorizationRequestUri());
    }
}
