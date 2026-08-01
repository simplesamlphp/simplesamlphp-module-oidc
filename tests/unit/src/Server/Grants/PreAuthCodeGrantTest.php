<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Grants;

use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\PreAuthCodeGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Stringable;

#[CoversClass(PreAuthCodeGrant::class)]
#[UsesClass(AuthCodeEntity::class)]
#[UsesClass(ResultBag::class)]
class PreAuthCodeGrantTest extends TestCase
{
    private const string PRE_AUTHORIZED_CODE = 'pre-authorized-code-secret';
    private const string TRANSACTION_CODE = '1234';
    private const string CLIENT_ID = 'wallet-client';

    private AuthCodeRepository&MockObject $authCodeRepositoryMock;
    private AccessTokenRepositoryInterface&MockObject $accessTokenRepositoryMock;
    private RefreshTokenRepositoryInterface&MockObject $refreshTokenRepositoryMock;
    private RequestRulesManager&MockObject $requestRulesManagerMock;
    private RequestParamsResolver&MockObject $requestParamsResolverMock;
    private AccessTokenEntityFactory&MockObject $accessTokenEntityFactoryMock;
    private AuthCodeEntityFactory&MockObject $authCodeEntityFactoryMock;
    private RefreshTokenIssuer&MockObject $refreshTokenIssuerMock;
    private Helpers&MockObject $helpersMock;
    private LoggerService&MockObject $loggerServiceMock;
    private ServerRequestInterface&MockObject $requestMock;

    /** @var array<int, array{message: string, context: array}> */
    private array $logRecords = [];

    protected function setUp(): void
    {
        $this->authCodeRepositoryMock = $this->createMock(AuthCodeRepository::class);
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepositoryInterface::class);
        $this->refreshTokenRepositoryMock = $this->createMock(RefreshTokenRepositoryInterface::class);
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);
        $this->authCodeEntityFactoryMock = $this->createMock(AuthCodeEntityFactory::class);
        $this->refreshTokenIssuerMock = $this->createMock(RefreshTokenIssuer::class);
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);

        $this->requestRulesManagerMock->method('check')->willReturn(new ResultBag());
        $this->captureLogs('debug');
        $this->captureLogs('notice');
        $this->captureLogs('warning');
        $this->captureLogs('error');
    }

    public function testRedeemsPreAuthorizedCodeOnlyAfterAtomicConsumption(): void
    {
        $this->configureRequestParameters(self::TRANSACTION_CODE);
        $authCode = $this->preAuthorizedCode(self::TRANSACTION_CODE);
        $accessToken = $this->createMock(AccessTokenEntity::class);
        $responseType = $this->createMock(ResponseTypeInterface::class);
        $operationOrder = [];

        $this->authCodeRepositoryMock->expects($this->once())
            ->method('findById')
            ->with(self::PRE_AUTHORIZED_CODE)
            ->willReturn($authCode);
        $this->authCodeRepositoryMock->expects($this->once())
            ->method('consumePreAuthorizedCode')
            ->with(self::PRE_AUTHORIZED_CODE)
            ->willReturnCallback(function () use (&$operationOrder): bool {
                $operationOrder[] = 'consume';
                return true;
            });

        $this->accessTokenEntityFactoryMock->expects($this->once())
            ->method('fromData')
            ->willReturn($accessToken);
        $this->accessTokenRepositoryMock->expects($this->once())
            ->method('persistNewAccessToken')
            ->with($accessToken)
            ->willReturnCallback(function () use (&$operationOrder): void {
                $operationOrder[] = 'persist';
            });
        $responseType->expects($this->once())->method('setAccessToken')->with($accessToken);

        $result = $this->sut()->respondToAccessTokenRequest(
            $this->requestMock,
            $responseType,
            new DateInterval('PT5M'),
        );

        $this->assertSame($responseType, $result);
        $this->assertSame(['consume', 'persist'], $operationOrder);
        $this->assertSecretsWereNotLogged(self::PRE_AUTHORIZED_CODE, self::TRANSACTION_CODE);
    }

    public function testRejectsReplayBeforeIssuingAnotherAccessToken(): void
    {
        $this->configureRequestParameters(null);
        $authCode = $this->preAuthorizedCode();

        $this->authCodeRepositoryMock->method('findById')->willReturn($authCode);
        $this->authCodeRepositoryMock->expects($this->once())
            ->method('consumePreAuthorizedCode')
            ->with(self::PRE_AUTHORIZED_CODE)
            ->willReturn(false);
        $this->accessTokenEntityFactoryMock->expects($this->never())->method('fromData');
        $this->accessTokenRepositoryMock->expects($this->never())->method('persistNewAccessToken');

        try {
            $this->sut()->respondToAccessTokenRequest(
                $this->requestMock,
                $this->createMock(ResponseTypeInterface::class),
                new DateInterval('PT5M'),
            );
            $this->fail('A replayed pre-authorized code must be rejected.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_grant', $exception->getErrorType());
        }

        $this->assertSecretsWereNotLogged(self::PRE_AUTHORIZED_CODE);
    }

    public function testRejectsInvalidTransactionCodeWithoutConsumingPreAuthorizedCode(): void
    {
        $submittedTransactionCode = '9999';
        $this->configureRequestParameters($submittedTransactionCode);
        $authCode = $this->preAuthorizedCode(self::TRANSACTION_CODE);

        $this->authCodeRepositoryMock->method('findById')->willReturn($authCode);
        $this->authCodeRepositoryMock->expects($this->never())->method('consumePreAuthorizedCode');
        $this->accessTokenRepositoryMock->expects($this->never())->method('persistNewAccessToken');

        try {
            $this->sut()->respondToAccessTokenRequest(
                $this->requestMock,
                $this->createMock(ResponseTypeInterface::class),
                new DateInterval('PT5M'),
            );
            $this->fail('An invalid transaction code must be rejected.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
        }

        $this->assertSecretsWereNotLogged(
            self::PRE_AUTHORIZED_CODE,
            self::TRANSACTION_CODE,
            $submittedTransactionCode,
        );
    }

    public function testTokenPersistenceFailureLeavesPreAuthorizedCodeConsumed(): void
    {
        $this->configureRequestParameters(null);
        $authCode = $this->preAuthorizedCode();
        $accessToken = $this->createMock(AccessTokenEntity::class);

        $this->authCodeRepositoryMock->expects($this->exactly(2))
            ->method('findById')
            ->with(self::PRE_AUTHORIZED_CODE)
            ->willReturn($authCode);
        $this->authCodeRepositoryMock->expects($this->exactly(2))
            ->method('consumePreAuthorizedCode')
            ->with(self::PRE_AUTHORIZED_CODE)
            ->willReturnOnConsecutiveCalls(true, false);
        $this->accessTokenEntityFactoryMock->expects($this->once())
            ->method('fromData')
            ->willReturn($accessToken);
        $this->accessTokenRepositoryMock->expects($this->once())
            ->method('persistNewAccessToken')
            ->with($accessToken)
            ->willThrowException(new RuntimeException('Access-token storage failed.'));

        try {
            $this->sut()->respondToAccessTokenRequest(
                $this->requestMock,
                $this->createMock(ResponseTypeInterface::class),
                new DateInterval('PT5M'),
            );
            $this->fail('The access-token persistence failure must be propagated.');
        } catch (RuntimeException $exception) {
            $this->assertSame('Access-token storage failed.', $exception->getMessage());
        }

        try {
            $this->sut()->respondToAccessTokenRequest(
                $this->requestMock,
                $this->createMock(ResponseTypeInterface::class),
                new DateInterval('PT5M'),
            );
            $this->fail('A retry after access-token persistence failure must be rejected.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_grant', $exception->getErrorType());
        }

        $this->assertSecretsWereNotLogged(self::PRE_AUTHORIZED_CODE);
    }

    private function sut(): PreAuthCodeGrant
    {
        return new PreAuthCodeGrant(
            $this->authCodeRepositoryMock,
            $this->accessTokenRepositoryMock,
            $this->refreshTokenRepositoryMock,
            new DateInterval('PT1M'),
            $this->requestRulesManagerMock,
            $this->requestParamsResolverMock,
            $this->accessTokenEntityFactoryMock,
            $this->authCodeEntityFactoryMock,
            $this->refreshTokenIssuerMock,
            $this->helpersMock,
            $this->loggerServiceMock,
        );
    }

    private function preAuthorizedCode(?string $transactionCode = null): AuthCodeEntity
    {
        $client = $this->createMock(ClientEntity::class);
        $client->method('getIdentifier')->willReturn(self::CLIENT_ID);

        return new AuthCodeEntity(
            self::PRE_AUTHORIZED_CODE,
            $client,
            [],
            new DateTimeImmutable('+1 hour'),
            'user-id',
            'openid-credential-offer://',
            flowTypeEnum: FlowTypeEnum::VciPreAuthorizedCode,
            txCode: $transactionCode,
        );
    }

    private function configureRequestParameters(?string $transactionCode): void
    {
        $this->requestParamsResolverMock->expects($this->never())->method('getAllFromRequest');
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')
            ->willReturnCallback(
                static fn(string $parameter): ?string => match ($parameter) {
                    ParamsEnum::PreAuthorizedCode->value => self::PRE_AUTHORIZED_CODE,
                    ParamsEnum::TxCode->value => $transactionCode,
                    ParamsEnum::ClientId->value => self::CLIENT_ID,
                    default => null,
                },
            );
    }

    private function captureLogs(string $level): void
    {
        $this->loggerServiceMock->method($level)->willReturnCallback(
            function (string|Stringable $message, array $context = []): void {
                $this->logRecords[] = ['message' => (string)$message, 'context' => $context];
            },
        );
    }

    private function assertSecretsWereNotLogged(string ...$secrets): void
    {
        $logs = json_encode($this->logRecords, JSON_THROW_ON_ERROR);
        foreach ($secrets as $secret) {
            $this->assertStringNotContainsString($secret, $logs);
        }
    }
}
