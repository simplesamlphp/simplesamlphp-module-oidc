<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Exceptions;

use Exception;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\ResponseModes\FragmentResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\OpenID\Codebooks\ErrorsEnum;

/**
 * The error responses this server can produce.
 *
 * These are protocol surface, not internal detail: a relying party branches on the `error` code, so the
 * code each factory produces and the status it is served with are part of the contract. The response
 * shape matters too -- an error carrying a redirect URI has to go back to the client as a redirect, and
 * one without it as a JSON body.
 */
#[CoversClass(OidcServerException::class)]
#[UsesClass(QueryResponseMode::class)]
#[UsesClass(FragmentResponseMode::class)]
class OidcServerExceptionTest extends TestCase
{
    /**
     * @param callable():OidcServerException $factory
     */
    #[DataProvider('errorProvider')]
    public function testProducesTheSpecifiedErrorCodeAndStatus(
        callable $factory,
        string $expectedErrorType,
        int $expectedStatusCode,
    ): void {
        $exception = $factory();

        $this->assertSame($expectedErrorType, $exception->getErrorType());
        $this->assertSame($expectedStatusCode, $exception->getHttpStatusCode());
        $this->assertSame($expectedErrorType, $exception->getPayload()['error']);
        $this->assertNotSame('', $exception->getPayload()['error_description']);
    }

    /**
     * @return array<string,array{0:callable():OidcServerException,1:string,2:int}>
     */
    public static function errorProvider(): array
    {
        return [
            'unsupported response type' => [
                static fn(): OidcServerException => OidcServerException::unsupportedResponseType(),
                'unsupported_response_type',
                400,
            ],
            'invalid scope' => [
                static fn(): OidcServerException => OidcServerException::invalidScope('bad-scope'),
                'invalid_scope',
                400,
            ],
            'invalid request' => [
                static fn(): OidcServerException => OidcServerException::invalidRequest('client_id'),
                'invalid_request',
                400,
            ],
            'access denied' => [
                static fn(): OidcServerException => OidcServerException::accessDenied(),
                'access_denied',
                401,
            ],
            'unauthorized client' => [
                static fn(): OidcServerException => OidcServerException::unauthorizedClient(),
                'unauthorized_client',
                400,
            ],
            'login required' => [
                static fn(): OidcServerException => OidcServerException::loginRequired(),
                'login_required',
                400,
            ],
            'request not supported' => [
                static fn(): OidcServerException => OidcServerException::requestNotSupported(),
                'request_not_supported',
                400,
            ],
            // An invalid refresh token is reported as invalid_grant, which is what RFC 6749 section 5.2
            // defines for a token that is expired, revoked or otherwise unusable.
            'invalid refresh token' => [
                static fn(): OidcServerException => OidcServerException::invalidRefreshToken(),
                'invalid_grant',
                400,
            ],
            'invalid trust chain' => [
                static fn(): OidcServerException => OidcServerException::invalidTrustChain(),
                ErrorsEnum::InvalidTrustChain->value,
                400,
            ],
            'forbidden' => [
                static fn(): OidcServerException => OidcServerException::forbidden(),
                'forbidden',
                403,
            ],
            'invalid client metadata' => [
                static fn(): OidcServerException => OidcServerException::invalidClientMetadata(),
                ErrorsEnum::InvalidClientMetadata->value,
                400,
            ],
            'invalid redirect uri' => [
                static fn(): OidcServerException => OidcServerException::invalidRedirectUri(),
                ErrorsEnum::InvalidRedirectUri->value,
                400,
            ],
        ];
    }

    public function testNamesTheOffendingParameterInAnInvalidRequest(): void
    {
        $description = OidcServerException::invalidRequest('redirect_uri')->getPayload()['error_description'];

        $this->assertStringContainsString('redirect_uri', $description);
    }

    public function testHintsDifferentlyDependingOnWhetherAScopeWasNamed(): void
    {
        // "check the scope you sent" is unhelpful when none was sent, so the empty case points at the
        // default scope setting instead.
        $named = OidcServerException::invalidScope('bad-scope')->getPayload()['error_description'];
        $this->assertStringContainsString('bad-scope', $named);

        $missing = OidcServerException::invalidScope('')->getPayload()['error_description'];
        $this->assertStringContainsString('default scope', $missing);
    }

    public function testAppendsTheHintToTheErrorDescription(): void
    {
        // The hint is what tells an integrator which of several ways the request was wrong.
        $description = OidcServerException::invalidRequest(
            'code_verifier',
            'Code Verifier must follow the specifications of RFC-7636.',
        )->getPayload()['error_description'];

        $this->assertStringContainsString('RFC-7636', $description);
    }

    public function testCarriesTheStateBackToTheClientWhenOneWasGiven(): void
    {
        // Without the state echoed back, a client cannot match the error to the request it sent.
        $withState = OidcServerException::accessDenied(null, null, null, 'opaque-state');
        $this->assertSame('opaque-state', $withState->getPayload()['state']);

        $this->assertArrayNotHasKey('state', OidcServerException::accessDenied()->getPayload());
    }

    public function testStateCanBeSetAndClearedAfterTheFact(): void
    {
        $exception = OidcServerException::accessDenied();

        $exception->setState('later-state');
        $this->assertSame('later-state', $exception->getPayload()['state']);

        $exception->setState(null);
        $this->assertArrayNotHasKey('state', $exception->getPayload());
    }

    public function testReportsWhetherItHasARedirectUri(): void
    {
        $this->assertFalse(OidcServerException::accessDenied()->hasRedirect());
        $this->assertNull(OidcServerException::accessDenied()->getRedirectUri());

        $withRedirect = OidcServerException::accessDenied(null, 'https://rp.example.org/callback');
        $this->assertTrue($withRedirect->hasRedirect());
        $this->assertSame('https://rp.example.org/callback', $withRedirect->getRedirectUri());

        $withRedirect->setRedirectUri(null);
        $this->assertFalse($withRedirect->hasRedirect());
    }

    public function testKeepsTheOriginalExceptionAsThePrevious(): void
    {
        $cause = new Exception('the underlying failure');

        $this->assertSame($cause, OidcServerException::forbidden(null, $cause)->getPrevious());
    }

    public function testRendersAnErrorWithNoRedirectUriAsAJsonBody(): void
    {
        $response = OidcServerException::invalidRequest('client_id')
            ->generateHttpResponse(new Response());

        $this->assertSame(400, $response->getStatusCode());

        $body = json_decode((string)$response->getBody(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertIsArray($body);
        $this->assertSame('invalid_request', $body['error']);
    }

    public function testRendersAnErrorWithARedirectUriAsARedirectCarryingTheErrorInTheQuery(): void
    {
        $response = OidcServerException::accessDenied(null, 'https://rp.example.org/callback', null, 'the-state')
            ->generateHttpResponse(new Response());

        $location = $response->getHeaderLine('location');

        $this->assertStringStartsWith('https://rp.example.org/callback?', $location);

        parse_str((string)parse_url($location, PHP_URL_QUERY), $query);

        $this->assertSame('access_denied', $query['error']);
        $this->assertSame('the-state', $query['state']);
    }

    public function testPutsTheErrorInTheFragmentWhenTheCallerAsksForIt(): void
    {
        // The implicit and hybrid flows return the response in the fragment, so their errors go there too,
        // which also keeps the error out of server logs and referrer headers along the way.
        $response = OidcServerException::accessDenied(null, 'https://rp.example.org/callback')
            ->generateHttpResponse(new Response(), useFragment: true);

        $location = $response->getHeaderLine('location');

        $this->assertStringStartsWith('https://rp.example.org/callback#', $location);

        parse_str((string)parse_url($location, PHP_URL_FRAGMENT), $fragment);

        $this->assertSame('access_denied', $fragment['error']);
    }

    public function testAnExplicitResponseModeWinsOverTheFragmentFlag(): void
    {
        $response = OidcServerException::accessDenied(
            null,
            'https://rp.example.org/callback',
            null,
            null,
            new QueryResponseMode(),
        )->generateHttpResponse(new Response(), useFragment: true);

        $this->assertStringStartsWith('https://rp.example.org/callback?', $response->getHeaderLine('location'));
    }
}
