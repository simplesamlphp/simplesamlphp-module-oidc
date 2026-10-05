<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
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
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\DpopJktRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

/**
 * The `dpop_jkt` authorization request parameter (RFC 9449 section 10), checked at the authorization endpoint and
 * the pushed authorization request endpoint. The code is bound to the key it names, so a value which can not be a
 * JWK SHA-256 thumbprint is refused rather than stored: a code bound to it could never be redeemed.
 */
#[CoversClass(DpopJktRule::class)]
#[UsesClass(Result::class)]
#[UsesClass(ResultBag::class)]
#[AllowMockObjectsWithoutExpectations]
class DpopJktRuleTest extends TestCase
{
    /** The example of RFC 9449 section 10, Figure 25. */
    private const string THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';


    protected RequestParamsResolver&MockObject $requestParamsResolverMock;

    protected ServerRequestInterface $request;

    protected ResultBag $resultBag;

    protected LoggerService&MockObject $loggerServiceMock;

    /** @var array<int, array{level: string, message: string, context: array}> */
    protected array $logRecords = [];


    protected function setUp(): void
    {
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->request = $this->createStub(ServerRequestInterface::class);

        $client = $this->createStub(ClientEntityInterface::class);
        $client->method('getIdentifier')->willReturn('client123');
        $this->resultBag = new ResultBag();
        $this->resultBag->add(new Result(ClientRule::class, $client));
        $this->resultBag->add(new Result(ClientRedirectUriRule::class, 'https://rp.example.org/callback'));
        $this->resultBag->add(new Result(StateRule::class, 'state123'));

        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        foreach (['debug', 'notice'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string $message, array $context = []) use ($level): void {
                    $this->logRecords[] = ['level' => $level, 'message' => $message, 'context' => $context];
                },
            );
        }
    }


    protected function check(mixed $dpopJkt): ?Result
    {
        $this->requestParamsResolverMock->method('getBasedOnAllowedMethods')->willReturn($dpopJkt);

        return (new DpopJktRule($this->requestParamsResolverMock, new Helpers()))->checkRule(
            $this->request,
            $this->resultBag,
            $this->loggerServiceMock,
            [],
            new QueryResponseMode(),
            [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
        );
    }


    /**
     * The parameter is read from the request, or from its Request Object, over the methods the endpoint allows.
     */
    public function testReadsTheParameterOverTheAllowedMethods(): void
    {
        $this->requestParamsResolverMock->expects($this->once())->method('getBasedOnAllowedMethods')
            ->with('dpop_jkt', $this->request, [HttpMethodsEnum::GET, HttpMethodsEnum::POST])
            ->willReturn(self::THUMBPRINT);

        $result = (new DpopJktRule($this->requestParamsResolverMock, new Helpers()))->checkRule(
            $this->request,
            $this->resultBag,
            $this->loggerServiceMock,
            [],
            new QueryResponseMode(),
            [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
        );

        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame(DpopJktRule::class, $result->getKey());
        $this->assertSame(self::THUMBPRINT, $result->getValue());
    }


    /**
     * A request without the parameter binds the code to nothing, and so does one which sends it without a value
     * (RFC 6749 section 3.1: such a parameter is treated as omitted).
     *
     * @return array<string, array{?string}>
     */
    public static function noKeyProvider(): array
    {
        return [
            'not sent' => [null],
            'sent without a value' => [''],
        ];
    }


    #[DataProvider('noKeyProvider')]
    public function testBindsToNothingWithoutAValue(?string $dpopJkt): void
    {
        $result = $this->check($dpopJkt);

        $this->assertInstanceOf(Result::class, $result);
        $this->assertNull($result->getValue());
    }


    public function testTakesAJwkSha256Thumbprint(): void
    {
        $this->assertSame(self::THUMBPRINT, $this->check(self::THUMBPRINT)?->getValue());
    }


    /**
     * @return array<string, array{mixed}>
     */
    public static function notAThumbprintProvider(): array
    {
        return [
            'one character short' => [substr(self::THUMBPRINT, 0, 42)],
            'one character long' => [self::THUMBPRINT . 'A'],
            'padded' => [self::THUMBPRINT . '='],
            'base64 rather than base64url' => [strtr(self::THUMBPRINT, '-_', '+/')],
            'a trailing line break' => [self::THUMBPRINT . "\n"],
            'a blank inside' => [substr(self::THUMBPRINT, 0, 20) . ' ' . substr(self::THUMBPRINT, 21)],
            'a list' => [[self::THUMBPRINT]],
            'a number' => [42],
        ];
    }


    /**
     * Anything but 43 characters of the base64url alphabet, which is what a SHA-256 hash comes to without
     * padding, is refused as `invalid_request`, sent back to the client's redirect URI with its state as the
     * other authorization request errors are. The value refused is not logged.
     */
    #[DataProvider('notAThumbprintProvider')]
    public function testRefusesAValueWhichIsNotAThumbprint(mixed $dpopJkt): void
    {
        try {
            $this->check($dpopJkt);
            $this->fail('The value must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertStringContainsString('dpop_jkt', (string)$exception->getHint());
            $this->assertSame('https://rp.example.org/callback', $exception->getRedirectUri());
            $this->assertSame('state123', $exception->getPayload()['state'] ?? null);
        }

        $this->assertSame(
            [['level' => 'notice', 'message' => 'Authorization request rejected: `dpop_jkt` is not a JWK SHA-256 ' .
                'thumbprint.', 'context' => ['client_id' => 'client123']]],
            array_values(array_filter(
                $this->logRecords,
                fn(array $record): bool => $record['level'] !== 'debug',
            )),
        );
    }
}
