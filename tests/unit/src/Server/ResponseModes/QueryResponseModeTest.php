<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\ResponseModes;

use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;

/**
 * The `query` response mode: the parameters go into the query string of the redirect URI, after a `?`,
 * or after an `&` when the URI already has a query. It is the response mode every request rule defaults
 * to, and the one `ResponseModeRule` picks for a request whose response type carries no token when the
 * request names none.
 *
 * The URI is read back off the redirect response as the Location header it generates, since the response
 * keeps the URI to itself.
 */
#[CoversClass(QueryResponseMode::class)]
class QueryResponseModeTest extends TestCase
{
    /**
     * @param array<string,string> $params
     */
    protected function locationOf(string $redirectUri, array $params): string
    {
        $response = (new QueryResponseMode())->buildResponse($redirectUri, $params);

        $this->assertInstanceOf(RedirectResponse::class, $response);

        return $response->generateHttpResponse(new Response())->getHeaderLine('Location');
    }


    #[DataProvider('redirectUriProvider')]
    public function testAppendsTheParametersAsTheQueryString(string $redirectUri, string $expected): void
    {
        $this->assertSame($expected, $this->locationOf($redirectUri, ['code' => 'abc123', 'state' => 'xyz']));
    }


    /**
     * @return array<string,array{string,string}>
     */
    public static function redirectUriProvider(): array
    {
        return [
            'no query yet' => [
                'https://rp.example.org/cb',
                'https://rp.example.org/cb?code=abc123&state=xyz',
            ],
            'a query already' => [
                'https://rp.example.org/cb?client=one',
                'https://rp.example.org/cb?client=one&code=abc123&state=xyz',
            ],
        ];
    }


    /**
     * Encoded as PHP's `http_build_query()` encodes: a space as a plus, the rest percent-encoded.
     */
    public function testEncodesTheParameterValues(): void
    {
        $this->assertSame(
            'https://rp.example.org/cb?state=a+b%26c%3Dd&code=%C3%A9',
            $this->locationOf('https://rp.example.org/cb', ['state' => 'a b&c=d', 'code' => 'é']),
        );
    }


    /**
     * Pinned as it stands: with nothing to append the separator is appended all the same.
     */
    public function testAppendsTheSeparatorEvenWithNothingToAppend(): void
    {
        $this->assertSame('https://rp.example.org/cb?', $this->locationOf('https://rp.example.org/cb', []));
    }
}
