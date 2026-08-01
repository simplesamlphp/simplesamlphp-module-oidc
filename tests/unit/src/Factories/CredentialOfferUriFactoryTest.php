<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use DateInterval;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\CredentialOfferUriFactory;
use SimpleSAML\Module\oidc\Factories\EmailFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\IssuerStateEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\UserIdentifierResolver;
use SimpleSAML\OpenID\VerifiableCredentials;
use SimpleSAML\Utils\Random;
use Stringable;

#[CoversClass(CredentialOfferUriFactory::class)]
#[UsesClass(AuthCodeEntity::class)]
class CredentialOfferUriFactoryTest extends TestCase
{
    /** @var array<int, array{message: string, context: array}> */
    private array $logRecords = [];

    public function testFallbackUserIdentifierDoesNotLogAttributesOrExceptionDetails(): void
    {
        $sensitiveAttributeValue = 'sensitive-user-attribute-value';
        $sensitiveExceptionValue = 'sensitive-resolver-exception-value';
        $userAttributes = [
            'displayName' => [$sensitiveAttributeValue],
            'privateClaim' => ['private-claim-value'],
        ];
        $logger = $this->createMock(LoggerService::class);
        $this->captureLogs($logger, 'warning');
        $this->captureLogs($logger, 'info');
        $userIdentifierResolver = $this->createMock(UserIdentifierResolver::class);
        $userIdentifierResolver->method('resolve')
            ->willThrowException(new RuntimeException($sensitiveExceptionValue));

        $client = $this->createMock(ClientEntity::class);
        $client->method('getIdentifier')->willReturn('vci-client');
        $authCode = new AuthCodeEntity(
            'pre-authorized-code-secret',
            $client,
            [],
            new DateTimeImmutable('+10 minutes'),
            'fallback-user',
            'openid-credential-offer://',
            flowTypeEnum: FlowTypeEnum::VciPreAuthorizedCode,
        );
        $authCodeEntityFactory = $this->createMock(AuthCodeEntityFactory::class);
        $authCodeEntityFactory->expects($this->once())->method('fromData')->willReturn($authCode);
        $authCodeRepository = $this->createMock(AuthCodeRepository::class);
        $authCodeRepository->expects($this->once())->method('persistNewAuthCode')->with($authCode);

        $clientRepository = $this->createMock(ClientRepository::class);
        $clientRepository->method('getGenericForVci')->willReturn($client);
        $userRepository = $this->createMock(UserRepository::class);
        $userRepository->method('getUserEntityByIdentifier')->willReturn(null);
        $userRepository->expects($this->once())->method('add');
        $userEntityFactory = $this->createMock(UserEntityFactory::class);
        $userEntityFactory->method('fromData')->willReturn(
            new UserEntity('fallback-user', new DateTimeImmutable(), new DateTimeImmutable(), $userAttributes),
        );

        $credentialOfferUri = $this->factory(
            $logger,
            $userIdentifierResolver,
            $authCodeRepository,
            $authCodeEntityFactory,
            $clientRepository,
            $userRepository,
            $userEntityFactory,
        )->buildPreAuthorized(['credential-configuration'], $userAttributes);

        $this->assertStringStartsWith('openid-credential-offer://?', $credentialOfferUri);
        $logs = json_encode($this->logRecords, JSON_THROW_ON_ERROR);
        $this->assertStringNotContainsString($sensitiveAttributeValue, $logs);
        $this->assertStringNotContainsString('private-claim-value', $logs);
        $this->assertStringNotContainsString($sensitiveExceptionValue, $logs);
    }

    public function testBuildTxCodeGeneratesFourDigitNumericCode(): void
    {
        $txCode = $this->factory(
            $this->createMock(LoggerService::class),
            $this->createMock(UserIdentifierResolver::class),
        )->buildTxCode('Enter the separately delivered code.');

        $this->assertMatchesRegularExpression('/^[0-9]{4}$/', $txCode->getCodeAsString());
    }

    private function factory(
        LoggerService $logger,
        UserIdentifierResolver $userIdentifierResolver,
        ?AuthCodeRepository $authCodeRepository = null,
        ?AuthCodeEntityFactory $authCodeEntityFactory = null,
        ?ClientRepository $clientRepository = null,
        ?UserRepository $userRepository = null,
        ?UserEntityFactory $userEntityFactory = null,
    ): CredentialOfferUriFactory {
        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('getVciCredentialConfigurationIdsSupported')
            ->willReturn(['credential-configuration']);
        $moduleConfig->method('getUserIdentifierAttributes')->willReturn(['uid']);
        $moduleConfig->method('getDefaultUsersEmailAttributeName')->willReturn('mail');
        $moduleConfig->method('getAuthCodeDuration')->willReturn(new DateInterval('PT10M'));
        $moduleConfig->method('getIssuer')->willReturn('https://issuer.example.org');

        $random = $this->createMock(Random::class);
        $random->method('generateID')->willReturn('pre-authorized-code-secret');
        $utils = $this->createMock(Utils::class);
        $utils->method('random')->willReturn($random);
        $sspBridge = $this->createMock(SspBridge::class);
        $sspBridge->method('utils')->willReturn($utils);

        return new CredentialOfferUriFactory(
            new VerifiableCredentials(),
            $moduleConfig,
            $sspBridge,
            $authCodeRepository ?? $this->createMock(AuthCodeRepository::class),
            $authCodeEntityFactory ?? $this->createMock(AuthCodeEntityFactory::class),
            $clientRepository ?? $this->createMock(ClientRepository::class),
            $logger,
            $userRepository ?? $this->createMock(UserRepository::class),
            $userEntityFactory ?? $this->createMock(UserEntityFactory::class),
            $this->createMock(EmailFactory::class),
            $this->createMock(IssuerStateEntityFactory::class),
            $this->createMock(IssuerStateRepository::class),
            $userIdentifierResolver,
        );
    }

    private function captureLogs(LoggerService&MockObject $logger, string $level): void
    {
        $logger->method($level)->willReturnCallback(
            function (string|Stringable $message, array $context = []): void {
                $this->logRecords[] = ['message' => (string)$message, 'context' => $context];
            },
        );
    }
}
