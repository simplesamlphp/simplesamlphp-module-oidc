<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeVerifierRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use Stringable;

/**
 * The PKCE code verifier check at the token endpoint.
 *
 * For a public client the verifier is the only thing standing between a stolen authorization code and an
 * access token, so both halves of this rule are security controls: that a public client cannot omit it,
 * and that what it sends conforms to RFC 7636 rather than being any string at all.
 */
#[CoversClass(CodeVerifierRule::class)]
#[UsesClass(Result::class)]
#[UsesClass(ResultBag::class)]
class CodeVerifierRuleTest extends TestCase
{
    private const string VALID_VERIFIER = 'M25iVXpKU3puUjFaYWg3T1NDTDQtcW1ROUY5YXlwalNoc0hhakxpZlRJUQ';
    private const string CLIENT_ID = 'client-id';

    private RequestParamsResolver&MockObject $requestParamsResolverMock;
    private ServerRequestInterface&MockObject $requestMock;
    private LoggerService&MockObject $loggerServiceMock;
    private ResponseModeInterface&MockObject $responseModeMock;

    /** @var array<int,array{message:string,context:array}> */
    private array $logRecords = [];

    protected function setUp(): void
    {
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->responseModeMock = $this->createMock(ResponseModeInterface::class);

        foreach (['debug', 'info', 'notice', 'warning', 'error'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string|Stringable $message, array $context = []): void {
                    $this->logRecords[] = ['message' => (string)$message, 'context' => $context];
                },
            );
        }
    }

    public function testRequiresTheClientToHaveBeenResolvedFirst(): void
    {
        // Whether a verifier may be omitted depends on the client, so running this rule without one is a
        // programming error rather than a bad request.
        $this->expectException(LogicException::class);

        $this->check(new ResultBag());
    }

    public function testRejectsAPublicClientThatSendsNoCodeVerifier(): void
    {
        // A public client has no secret, so without PKCE nothing binds the code to whoever requested it.
        $this->resolverReturns(null);

        try {
            $this->check($this->resultBagFor($this->client(isConfidential: false)));
            $this->fail('A public client must not be able to redeem a code without a code_verifier.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
        }
    }

    public function testAllowsAConfidentialClientToOmitTheCodeVerifier(): void
    {
        // A confidential client authenticates with its credentials, so PKCE is optional for it.
        $this->resolverReturns(null);

        $result = $this->check($this->resultBagFor($this->client(isConfidential: true)));

        $this->assertInstanceOf(Result::class, $result);
        $this->assertNull($result->getValue());
    }

    #[DataProvider('malformedVerifierProvider')]
    public function testRejectsACodeVerifierThatDoesNotFollowRfc7636(string $verifier, string $why): void
    {
        $this->resolverReturns($verifier);

        try {
            $this->check($this->resultBagFor($this->client()));
            $this->fail(sprintf('A code_verifier that is %s must be rejected.', $why));
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
        }
    }

    /**
     * @return array<string,array{0:string,1:string}>
     */
    public static function malformedVerifierProvider(): array
    {
        return [
            'one character short of the minimum' => [str_repeat('a', 42), 'shorter than 43 characters'],
            'one character past the maximum' => [str_repeat('a', 129), 'longer than 128 characters'],
            'empty' => ['', 'empty'],
            'contains a character outside the unreserved set' => [
                str_repeat('a', 42) . '+',
                'outside the unreserved character set',
            ],
            'contains a space' => [str_repeat('a', 42) . ' ', 'containing a space'],
        ];
    }

    #[DataProvider('validVerifierProvider')]
    public function testAcceptsACodeVerifierWithinTheAllowedBounds(string $verifier): void
    {
        $this->resolverReturns($verifier);

        $this->assertSame($verifier, $this->check($this->resultBagFor($this->client()))?->getValue());
    }

    /**
     * @return array<string,array{0:string}>
     */
    public static function validVerifierProvider(): array
    {
        return [
            'the shortest allowed' => [str_repeat('a', 43)],
            'the longest allowed' => [str_repeat('a', 128)],
            'every character of the unreserved set' => ['abcXYZ019' . str_repeat('-._~', 9)],
            'a realistic verifier' => [self::VALID_VERIFIER],
        ];
    }

    public function testDoesNotLogTheCodeVerifierItWasGiven(): void
    {
        // The verifier is a credential: it is what proves the caller started the authorization.
        $this->resolverReturns('not a valid verifier');

        try {
            $this->check($this->resultBagFor($this->client()));
        } catch (OidcServerException) {
            // The rejection is asserted elsewhere; what matters here is what reached the log.
        }

        $this->assertStringNotContainsString(
            'not a valid verifier',
            json_encode($this->logRecords, JSON_THROW_ON_ERROR),
        );
    }

    private function resolverReturns(?string $codeVerifier): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturn($codeVerifier);
    }

    private function client(bool $isConfidential = true): ClientEntityInterface&MockObject
    {
        $client = $this->createMock(ClientEntityInterface::class);
        $client->method('isConfidential')->willReturn($isConfidential);
        $client->method('getIdentifier')->willReturn(self::CLIENT_ID);

        return $client;
    }

    private function resultBagFor(ClientEntityInterface $client): ResultBag
    {
        $resultBag = new ResultBag();
        $resultBag->add(new Result(ClientRule::class, $client));

        return $resultBag;
    }

    private function check(ResultBag $resultBag): ?Result
    {
        $rule = new CodeVerifierRule($this->requestParamsResolverMock, new Helpers());

        return $rule->checkRule(
            $this->requestMock,
            $resultBag,
            $this->loggerServiceMock,
            [],
            $this->responseModeMock,
        );
    }
}
