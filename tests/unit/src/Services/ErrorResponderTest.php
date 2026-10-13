<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use League\OAuth2\Server\Exception\OAuthServerException;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;

#[CoversClass(ErrorResponder::class)]
#[AllowMockObjectsWithoutExpectations]
class ErrorResponderTest extends TestCase
{
    /**
     * A description with the characters on either side of each bound RFC 6749 sets for one (%x20-21 / %x23-5B /
     * %x5D-7E): the space, '!', '#', '[', ']' and '~' allowed, the double quote, the backslash, DEL, a control
     * character, a tab, a line feed and two non-ASCII characters not.
     */
    private const string DESCRIPTION = "a !#[]~ \"\\\x7F\x1F\t\n\u{E9}\u{2713}z";

    /**
     * DESCRIPTION with only the characters it may hold.
     */
    private const string DESCRIPTION_KEPT = 'a !#[]~ z';


    protected MockObject $psrHttpBridgeMock;

    protected MockObject $loggerServiceMock;


    protected function setUp(): void
    {
        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }


    protected function sut(): ErrorResponder
    {
        return new ErrorResponder($this->psrHttpBridgeMock, $this->loggerServiceMock);
    }


    public function testForExceptionJsonLogsClientErrorAsNotice(): void
    {
        $this->loggerServiceMock->expects($this->once())->method('notice');
        $this->loggerServiceMock->expects($this->never())->method('warning');
        $this->loggerServiceMock->expects($this->never())->method('error');

        $response = $this->sut()->forExceptionJson(OidcServerException::invalidRequest('client_id'));

        $this->assertSame(400, $response->getStatusCode());
    }


    public function testForExceptionJsonLogsAccessDeniedAsWarning(): void
    {
        $this->loggerServiceMock->expects($this->once())->method('warning');
        $this->loggerServiceMock->expects($this->never())->method('error');

        $response = $this->sut()->forExceptionJson(OidcServerException::accessDenied('nope'));

        $this->assertSame(401, $response->getStatusCode());
    }


    public function testForExceptionJsonLogsServerErrorAsError(): void
    {
        $this->loggerServiceMock->expects($this->once())->method('error');
        $this->loggerServiceMock->expects($this->never())->method('notice');

        $response = $this->sut()->forExceptionJson(OAuthServerException::serverError('boom'));

        $this->assertSame(500, $response->getStatusCode());
    }


    /**
     * A refused access token carries its challenge, naming the error (RFC 6750 section 3.1), next to the body.
     */
    public function testForExceptionJsonCarriesTheChallengeOfARefusedAccessToken(): void
    {
        $response = $this->sut()->forExceptionJson(OidcServerException::invalidToken('Access token has been revoked'));

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('Bearer error="invalid_token"', $response->headers->get('WWW-Authenticate'));
        $this->assertStringContainsString('no-store', (string)$response->headers->get('Cache-Control'));

        $body = json_decode((string)$response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertIsArray($body);
        $this->assertSame('invalid_token', $body['error']);
        $this->assertSame('Access token has been revoked', $body['hint']);
    }


    /**
     * A request which carried no access token gets the bare challenge and no body, so no error code (RFC 6750
     * section 3.1). It is logged all the same, as every refusal is.
     */
    public function testForExceptionJsonAnswersAMissingAccessTokenWithTheBareChallengeAlone(): void
    {
        $this->loggerServiceMock->expects($this->once())->method('warning')
            ->with($this->stringContains('missing_token'));

        $response = $this->sut()->forExceptionJson(OidcServerException::missingToken('No Bearer access token.'));

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('Bearer', $response->headers->get('WWW-Authenticate'));
        $this->assertSame('', $response->getContent());
        $this->assertFalse($response->headers->has('Content-Type'));
        $this->assertStringContainsString('no-store', (string)$response->headers->get('Cache-Control'));
    }


    /**
     * @return array<string,array{0:\League\OAuth2\Server\Exception\OAuthServerException}>
     */
    public static function errorWithoutAChallengeProvider(): array
    {
        return [
            'a request error' => [OidcServerException::invalidRequest('client_id')],
            'a denial' => [OidcServerException::accessDenied('nope')],
            "League's own" => [OAuthServerException::serverError('boom')],
            'a client which did not authenticate through the Authorization header' => [
                OidcServerException::invalidClient(
                    (new Psr17Factory())->createServerRequest('POST', 'https://op.example.org/par'),
                ),
            ],
        ];
    }


    /**
     * A client which failed to authenticate through the Authorization header gets the challenge of its scheme
     * (RFC 6749 section 5.2) at the PAR endpoint too, which answers in this format (RFC 9126 section 2.3).
     */
    public function testForExceptionJsonCarriesTheChallengeOfAClientWhichFailedToAuthenticate(): void
    {
        $request = (new Psr17Factory())->createServerRequest('POST', 'https://op.example.org/par')
            ->withHeader('Authorization', 'Basic ' . base64_encode('client-id:wrong-secret'));

        $response = $this->sut()->forExceptionJson(OidcServerException::invalidClient($request));

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('Basic realm="OAuth"', $response->headers->get('WWW-Authenticate'));
        $body = json_decode((string)$response->getContent(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertIsArray($body);
        $this->assertSame('invalid_client', $body['error']);
    }


    /**
     * The description keeps to the characters RFC 6749 allows in one, whatever the message held.
     */
    public function testForExceptionJsonKeepsTheDescriptionToTheCharactersItMayHold(): void
    {
        $response = $this->sut()->forExceptionJson(new OAuthServerException(self::DESCRIPTION, 0, 'invalid_request'));

        $body = json_decode((string)$response->getContent(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertIsArray($body);
        $this->assertSame(self::DESCRIPTION_KEPT, $body['error_description']);
    }


    /**
     * The same in League's rendering, of League's exception and of this module's, which writes the hint into
     * the description.
     */
    public function testForExceptionKeepsTheDescriptionToTheCharactersItMayHold(): void
    {
        $sut = $this->sutWithARealBridge();

        $leagues = $sut->forException(new OAuthServerException(self::DESCRIPTION, 0, 'invalid_grant'));
        $modules = $sut->forException(OidcServerException::invalidRequest('code', self::DESCRIPTION));

        $leaguesBody = json_decode((string)$leagues->getContent(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertIsArray($leaguesBody);
        $this->assertSame(self::DESCRIPTION_KEPT, $leaguesBody['error_description']);
        $modulesBody = json_decode((string)$modules->getContent(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertIsArray($modulesBody);
        $this->assertStringEndsWith('(' . self::DESCRIPTION_KEPT . ')', $modulesBody['error_description']);
    }


    /**
     * And in an error sent back to the redirect URI, the authorization endpoint's (RFC 6749 section 4.1.2.1).
     */
    public function testForExceptionKeepsTheDescriptionOfARedirectedErrorToTheCharactersItMayHold(): void
    {
        $response = $this->sutWithARealBridge()->forException(OidcServerException::invalidRequest(
            'scope',
            self::DESCRIPTION,
            null,
            'https://client.example.org/callback',
            'state-of-the-client',
        ));

        $this->assertSame(302, $response->getStatusCode());
        $location = (string)$response->headers->get('Location');
        $this->assertStringStartsWith('https://client.example.org/callback?', $location);
        parse_str((string)parse_url($location, PHP_URL_QUERY), $query);
        $this->assertSame('invalid_request', $query['error'] ?? null);
        $this->assertSame('state-of-the-client', $query['state'] ?? null);
        $this->assertIsString($query['error_description'] ?? null);
        $this->assertStringEndsWith('(' . self::DESCRIPTION_KEPT . ')', $query['error_description']);
    }


    #[DataProvider('errorWithoutAChallengeProvider')]
    public function testForExceptionJsonAddsNoChallengeToAnyOtherError(OAuthServerException $exception): void
    {
        $response = $this->sut()->forExceptionJson($exception);

        $this->assertFalse($response->headers->has('WWW-Authenticate'));

        $body = json_decode((string)$response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertIsArray($body);
        $this->assertSame($exception->getErrorType(), $body['error']);
    }


    /**
     * The League-style answer (the UserInfo endpoint's) carries the same challenge and the same absence of a
     * body as the JSON one, through the exception's own headers and rendering.
     */
    public function testForExceptionCarriesTheChallengeOfAProtectedResourceRefusal(): void
    {
        $psr17Factory = new Psr17Factory();
        $sut = new ErrorResponder(
            new PsrHttpBridge(new HttpFoundationFactory(), $psr17Factory, $psr17Factory, $psr17Factory, $psr17Factory),
            $this->loggerServiceMock,
        );

        $refused = $sut->forException(OidcServerException::invalidToken('Access token has been revoked'));

        $this->assertSame(401, $refused->getStatusCode());
        $this->assertSame('Bearer error="invalid_token"', $refused->headers->get('WWW-Authenticate'));
        $body = json_decode((string)$refused->getContent(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertIsArray($body);
        $this->assertSame('invalid_token', $body['error']);

        $missing = $sut->forException(OidcServerException::missingToken('No Bearer access token.'));

        $this->assertSame(401, $missing->getStatusCode());
        $this->assertSame('Bearer', $missing->headers->get('WWW-Authenticate'));
        $this->assertSame('', $missing->getContent());
        $this->assertFalse($missing->headers->has('Content-Type'));
    }


    protected function sutWithARealBridge(): ErrorResponder
    {
        $psr17Factory = new Psr17Factory();

        return new ErrorResponder(
            new PsrHttpBridge(new HttpFoundationFactory(), $psr17Factory, $psr17Factory, $psr17Factory, $psr17Factory),
            $this->loggerServiceMock,
        );
    }


    public function testForExceptionLogsUnexpectedThrowableAsError(): void
    {
        $this->loggerServiceMock->expects($this->once())->method('error');

        $response = $this->sut()->forException(new RuntimeException('unexpected'));

        $this->assertSame(500, $response->getStatusCode());
    }
}
