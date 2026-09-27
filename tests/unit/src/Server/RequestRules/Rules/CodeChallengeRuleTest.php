<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use LogicException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use Stringable;

/**
 * The PKCE (RFC 7636) code challenge check at the authorization endpoint.
 *
 * A public client has no secret, so this challenge and the verifier checked against it at the token
 * endpoint are what bind an authorization code to the software which asked for it. Refusing a public
 * client which sends no challenge, and refusing a challenge which does not follow RFC-7636, are
 * therefore security controls rather than input tidiness. The token endpoint half is in
 * `CodeVerifierRuleTest`.
 *
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeRule
 */
#[AllowMockObjectsWithoutExpectations]
class CodeChallengeRuleTest extends TestCase
{
    private const string CLIENT_ID = 'client123';


    protected CodeChallengeRule $rule;

    protected Stub $requestStub;

    protected Stub $resultBagStub;

    protected Result $redirectUriResult;

    protected Result $stateResult;

    protected string $codeChallenge = '123123123123123123123123123123123123123123123123123123123123';

    protected LoggerService&MockObject $loggerServiceMock;

    /** @var array<int,array{level:string,message:string,context:array}> */
    protected array $logRecords = [];

    protected Stub $requestParamsResolverStub;

    protected Stub $clientStub;

    protected Result $clientIdResult;

    protected Helpers $helpers;

    protected Stub $responseModeStub;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->redirectUriResult = new Result(ClientRedirectUriRule::class, 'https://some-uri.org');
        $this->stateResult = new Result(StateRule::class, '123');
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        foreach (['debug', 'info', 'notice', 'warning', 'error'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string|Stringable $message, array $context = []) use ($level): void {
                    $this->logRecords[] = [
                        'level' => $level,
                        'message' => (string)$message,
                        'context' => $context,
                    ];
                },
            );
        }
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->clientStub = $this->createStub(ClientEntityInterface::class);
        $this->clientIdResult = new Result(ClientRule::class, $this->clientStub);
        $this->helpers = new Helpers();
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
    }


    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
    ): CodeChallengeRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;

        return new CodeChallengeRule(
            $requestParamsResolver,
            $helpers,
        );
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleRedirectUriDependency(): void
    {
        $resultBag = new ResultBag();
        $this->expectException(LogicException::class);
        $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceMock, [], $this->responseModeStub);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleStateDependency(): void
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $this->expectException(LogicException::class);
        $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceMock, [], $this->responseModeStub);
    }


    /**
     * @throws \Throwable
     */
    public function testCheckRuleNoCodeReturnsNullForConfidentialClients(): void
    {
        $this->clientStub->method('isConfidential')->willReturn(true);
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn(null);
        $result = $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
        $this->assertInstanceOf(Result::class, $result);
        $this->assertNull($result->getValue());
    }


    /**
     * A challenge which is present is held to RFC-7636's shape (43 to 128 unreserved characters) whoever
     * sent it. An empty value is one of these rather than an absent challenge: the request params resolver
     * casts a present-but-empty param to '', which is not null, so a public client which sends
     * `code_challenge=` is answered for the shape and not for the missing challenge.
     *
     * @return array<string,array{0:string,1:bool}>
     */
    public static function malformedCodeChallengeProvider(): array
    {
        return [
            'one character short of the minimum' => [str_repeat('a', 42), false],
            'one character past the maximum' => [str_repeat('a', 129), false],
            'empty, which the resolver reports as a present param' => ['', false],
            'standard base64 rather than base64url (+)' => [str_repeat('a', 42) . '+', false],
            'standard base64 rather than base64url (/)' => [str_repeat('a', 42) . '/', false],
            'base64 padding' => [str_repeat('a', 42) . '=', false],
            'a space' => [str_repeat('a', 42) . ' ', false],
            // Only a single *trailing* newline slips past the pattern (7.21); these do not.
            'a leading newline' => ["\n" . str_repeat('a', 43), false],
            'an embedded newline' => [str_repeat('a', 20) . "\n" . str_repeat('a', 23), false],
            'two trailing newlines' => [str_repeat('a', 43) . "\n\n", false],
            'a trailing carriage return' => [str_repeat('a', 43) . "\r", false],
            'a trailing null byte' => [str_repeat('a', 43) . "\0", false],
            'a confidential client is held to the same shape' => [str_repeat('a', 42), true],
        ];
    }


    /**
     * @throws \Throwable
     */
    #[DataProvider('malformedCodeChallengeProvider')]
    public function testCheckRuleInvalidCodeChallengeThrows(string $codeChallenge, bool $isConfidential): void
    {
        // The rule fixes the shape RFC-7636 gives a challenge -- 43 to 128 unreserved characters -- so a
        // value outside it cannot be the transformation of any verifier the token endpoint will see.
        $this->clientStub->method('isConfidential')->willReturn($isConfidential);
        $this->clientStub->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn($codeChallenge);

        try {
            $this->sut()->checkRule(
                $this->requestStub,
                $this->prepareValidResultBag(),
                $this->loggerServiceMock,
                [],
                $this->responseModeStub,
            );
            $this->fail('A code_challenge which does not follow RFC-7636 must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertSame('Code Challenge must follow the specifications of RFC-7636.', $exception->getHint());
            $this->assertSame('https://some-uri.org', $exception->getRedirectUri());
            $this->assertSame('123', $exception->getPayload()['state']);
        }

        $this->assertSame(
            [
                [
                    'message' => 'Authorization request rejected: `code_challenge` does not follow RFC-7636 ' .
                        '(wrong length or character set).',
                    'context' => ['client_id' => self::CLIENT_ID],
                ],
            ],
            $this->logRecordsOfLevel('notice'),
        );
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleForValidCodeChallenge(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn($this->codeChallenge);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );

        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame($this->codeChallenge, $result->getValue());
    }


    /**
     * @throws \Throwable
     */
    public function testRefusesAPublicClientWhichSendsNoCodeChallenge(): void
    {
        // Without a challenge there is nothing for the token endpoint to check a verifier against, so a
        // stolen authorization code would be redeemable by whoever holds it.
        $this->clientStub->method('isConfidential')->willReturn(false);
        $this->clientStub->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn(null);

        try {
            $this->sut()->checkRule(
                $this->requestStub,
                $this->prepareValidResultBag(),
                $this->loggerServiceMock,
                [],
                $this->responseModeStub,
            );
            $this->fail('A public client which sends no code_challenge must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertSame(400, $exception->getHttpStatusCode());
            $this->assertSame('Code Challenge must be provided for public clients.', $exception->getHint());
            $this->assertSame('https://some-uri.org', $exception->getRedirectUri());
            $payload = $exception->getPayload();
            $this->assertSame('invalid_request', $payload['error']);
            // The hint reaches the client in the error description (`OidcServerException::create()`).
            $this->assertStringEndsWith(
                '(Code Challenge must be provided for public clients.)',
                (string)$payload['error_description'],
            );
            $this->assertSame('123', $payload['state']);
        }

        $this->assertSame(
            [
                [
                    'message' => 'Authorization request rejected: `code_challenge` (PKCE) is required for ' .
                        'public clients.',
                    'context' => ['client_id' => self::CLIENT_ID],
                ],
            ],
            $this->logRecordsOfLevel('notice'),
        );
    }


    /**
     * PCRE's `$` matches at the end of the subject or before a final newline, and the rule's pattern uses
     * neither `\z` nor the `D` modifier, so a challenge of valid shape followed by one newline is accepted
     * today (a carriage return is not: it is not `$`'s exception). Pinned as it stands, with the fix queued
     * as 7.21 -- the same pattern is in `CodeVerifierRule.php:61`, so both halves of PKCE take it together.
     * Nothing is bypassed by it: such a challenge is still redeemable only by a verifier which hashes to it.
     *
     * @throws \Throwable
     */
    /**
     * @return array<string,array{0:string}>
     */
    public static function newlineTerminatedCodeChallengeProvider(): array
    {
        return [
            'the shortest allowed, plus a newline' => [str_repeat('a', 43) . "\n"],
            // 129 characters, so the laxness widens the maximum by one as well as the character set.
            'the longest allowed, plus a newline' => [str_repeat('a', 128) . "\n"],
        ];
    }


    #[DataProvider('newlineTerminatedCodeChallengeProvider')]
    public function testAcceptsACodeChallengeWithOneTrailingNewline(string $codeChallenge): void
    {
        $this->clientStub->method('isConfidential')->willReturn(false);
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn($codeChallenge);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->prepareValidResultBag(),
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );

        $this->assertSame($codeChallenge, $result?->getValue());
        $this->assertSame([], $this->logRecordsOfLevel('notice'));
    }


    /**
     * The records of one level, so that a test pins the event it is about without being coupled to the
     * rule's entry trace.
     *
     * @return array<int,array{message:string,context:array}>
     */
    protected function logRecordsOfLevel(string $level): array
    {
        return array_values(array_map(
            static fn(array $record): array => ['message' => $record['message'], 'context' => $record['context']],
            array_filter($this->logRecords, static fn(array $record): bool => $record['level'] === $level),
        ));
    }


    protected function prepareValidResultBag(): ResultBag
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        $resultBag->add($this->clientIdResult);
        return $resultBag;
    }
}
