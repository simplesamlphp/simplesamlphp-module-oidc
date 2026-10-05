<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Exceptions;

use Exception;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\ResponseModes\FragmentResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\OpenID\Codebooks\AccessTokenTypesEnum;
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
#[AllowMockObjectsWithoutExpectations]
class OidcServerExceptionTest extends TestCase
{
    /**
     * @param callable():\SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException $factory
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
     * @return array<string,array{0:callable():\SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException,1:string,2:int}>
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
            'invalid authorization details' => [
                static fn(): OidcServerException => OidcServerException::invalidAuthorizationDetails('Not offered.'),
                'invalid_authorization_details',
                400,
            ],
            'access denied' => [
                static fn(): OidcServerException => OidcServerException::accessDenied(),
                'access_denied',
                401,
            ],
            'invalid token' => [
                static fn(): OidcServerException => OidcServerException::invalidToken(),
                'invalid_token',
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


    /**
     * Refused authorization details go back to the redirect URI with the state, as any other refusal of an
     * authorization request does, and with the hint saying what was wrong with them.
     */
    public function testRefusesAuthorizationDetailsBackToTheClientWithTheStateAndTheHint(): void
    {
        $exception = OidcServerException::invalidAuthorizationDetails(
            'The Credential Offer did not offer the credential configuration requested.',
            'https://wallet.example.org/callback',
            'opaque-state',
        );

        $this->assertSame('https://wallet.example.org/callback', $exception->getRedirectUri());
        $this->assertSame('opaque-state', $exception->getPayload()['state'] ?? null);
        $this->assertStringContainsString('did not offer', $exception->getPayload()['error_description']);
        $this->assertFalse(OidcServerException::invalidAuthorizationDetails('Not granted.')->hasRedirect());
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


    /**
     * A refused access token is named in the challenge as well as in the body (RFC 6750 section 3.1), so that a
     * client which reads only the header learns it too.
     */
    public function testRendersARefusedAccessTokenWithAChallengeNamingTheError(): void
    {
        $exception = OidcServerException::invalidToken('Access token has been revoked');

        $this->assertSame('Bearer error="invalid_token"', $exception->getWwwAuthenticate());
        $this->assertTrue($exception->hasBody());

        $response = $exception->generateHttpResponse(new Response());

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('Bearer error="invalid_token"', $response->getHeaderLine('WWW-Authenticate'));
        $this->assertSame('application/json', $response->getHeaderLine('Content-type'));

        $body = json_decode((string)$response->getBody(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertIsArray($body);
        $this->assertSame('invalid_token', $body['error']);
        $this->assertStringContainsString('Access token has been revoked', (string)$body['error_description']);
    }


    /**
     * The challenge of another scheme, given by the caller, is the one sent: a token presented under the DPoP
     * scheme is refused under it (RFC 9449 section 7.1).
     */
    public function testRendersARefusedAccessTokenWithTheChallengeGiven(): void
    {
        $exception = OidcServerException::invalidToken('Not bound.', null, 'DPoP error="invalid_token", algs="ES256"');

        $response = $exception->generateHttpResponse(new Response());

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('DPoP error="invalid_token", algs="ES256"', $response->getHeaderLine('WWW-Authenticate'));
    }


    /**
     * @return array<string,array{0:\SimpleSAML\OpenID\Codebooks\AccessTokenTypesEnum,1:?string,2:string[],3:string}>
     */
    public static function challengeProvider(): array
    {
        return [
            'the Bearer scheme alone' => [AccessTokenTypesEnum::Bearer, null, [], 'Bearer'],
            'a Bearer error' => [AccessTokenTypesEnum::Bearer, 'invalid_token', [], 'Bearer error="invalid_token"'],
            'the DPoP algorithms alone' => [
                AccessTokenTypesEnum::DPoP,
                null,
                ['ES256', 'PS256'],
                'DPoP algs="ES256 PS256"',
            ],
            'a DPoP error' => [
                AccessTokenTypesEnum::DPoP,
                'invalid_dpop_proof',
                ['ES256'],
                'DPoP error="invalid_dpop_proof", algs="ES256"',
            ],
        ];
    }


    /**
     * A challenge is the scheme, then its parameters separated by commas (RFC 9110 section 11.6.1): the error, and
     * for DPoP the algorithms, separated by spaces (RFC 9449 section 7.1).
     *
     * @param string[] $algs
     */
    #[DataProvider('challengeProvider')]
    public function testBuildsAChallenge(
        AccessTokenTypesEnum $scheme,
        ?string $error,
        array $algs,
        string $expected,
    ): void {
        $this->assertSame($expected, OidcServerException::buildChallenge($scheme, $error, $algs));
    }


    /**
     * At the token endpoint an invalid DPoP proof is the 400 token error response of RFC 9449 section 5, with no
     * challenge.
     */
    public function testRendersAnInvalidDpopProofWithoutAChallengeAsTheTokenEndpointsRefusal(): void
    {
        $exception = OidcServerException::invalidDpopProof('The DPoP proof has been used before.');

        $this->assertNull($exception->getWwwAuthenticate());

        $response = $exception->generateHttpResponse(new Response());

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('WWW-Authenticate'));
        $body = json_decode((string)$response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertIsArray($body);
        $this->assertSame('invalid_dpop_proof', $body['error']);
    }


    /**
     * At a protected resource it is section 7.1's 401, with the DPoP challenge the caller gives.
     */
    public function testRendersAnInvalidDpopProofWithAChallengeAsAProtectedResourcesRefusal(): void
    {
        $challenge = 'DPoP error="invalid_dpop_proof", algs="ES256"';
        $exception = OidcServerException::invalidDpopProof('No proof.', $challenge);

        $response = $exception->generateHttpResponse(new Response());

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame($challenge, $response->getHeaderLine('WWW-Authenticate'));
        $body = json_decode((string)$response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertIsArray($body);
        $this->assertSame('invalid_dpop_proof', $body['error']);
    }


    /**
     * A token presented more than one way is `invalid_request` with a 400 (RFC 6750 section 3.1), with the
     * challenge the caller gives and Figure 19's description.
     */
    public function testRendersMoreThanOneTokenMethodAsAnInvalidRequest(): void
    {
        $exception = OidcServerException::multipleAccessTokenMethods('Bearer error="invalid_request"');

        $response = $exception->generateHttpResponse(new Response());

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('Bearer error="invalid_request"', $response->getHeaderLine('WWW-Authenticate'));
        $body = json_decode((string)$response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertIsArray($body);
        $this->assertSame('invalid_request', $body['error']);
        $this->assertStringContainsString('Multiple methods used to include access token', $body['error_description']);
    }


    /**
     * A request which carried no access token gets the bare challenge and nothing else (RFC 6750 section 3.1): no
     * error code, so no body and no content type claiming one. The error type names the refusal in the log only.
     */
    public function testRendersAMissingAccessTokenAsTheBareChallengeAlone(): void
    {
        $exception = OidcServerException::missingToken('No Bearer access token.');

        $this->assertSame(401, $exception->getHttpStatusCode());
        $this->assertSame('missing_token', $exception->getErrorType());
        $this->assertSame('Bearer', $exception->getWwwAuthenticate());
        $this->assertFalse($exception->hasBody());
        $this->assertSame([], $exception->getPayload());

        $response = $exception->generateHttpResponse(new Response());

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(['WWW-Authenticate' => ['Bearer']], $response->getHeaders());
        $this->assertSame('', (string)$response->getBody());
    }


    /**
     * A request which tried another scheme gets that scheme's challenge, still without error information and body.
     */
    public function testRendersAMissingAccessTokenWithTheChallengeGiven(): void
    {
        $exception = OidcServerException::missingToken('No token.', 'DPoP algs="ES256"');

        $response = $exception->generateHttpResponse(new Response());

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(['WWW-Authenticate' => ['DPoP algs="ES256"']], $response->getHeaders());
        $this->assertSame('', (string)$response->getBody());
    }


    /**
     * @return array<string,array{0:callable():\SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException}>
     */
    public static function errorWithoutAChallengeProvider(): array
    {
        return [
            'access denied' => [static fn(): OidcServerException => OidcServerException::accessDenied()],
            'invalid request' => [
                static fn(): OidcServerException => OidcServerException::invalidRequest('client_id'),
            ],
            'server error' => [static fn(): OidcServerException => OidcServerException::serverError('boom')],
        ];
    }


    /**
     * @param callable():\SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException $factory
     */
    #[DataProvider('errorWithoutAChallengeProvider')]
    public function testAnyOtherErrorCarriesNoChallengeAndAJsonBody(callable $factory): void
    {
        $exception = $factory();

        $this->assertNull($exception->getWwwAuthenticate());
        $this->assertTrue($exception->hasBody());
        $this->assertSame(['Content-type' => 'application/json'], $exception->getHttpHeaders());
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
