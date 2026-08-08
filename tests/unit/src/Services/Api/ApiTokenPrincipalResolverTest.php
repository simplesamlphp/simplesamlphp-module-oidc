<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services\Api;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\Api\ApiTokenPrincipalResolver;
use SimpleSAML\Module\oidc\Services\LoggerService;

#[CoversClass(ApiTokenPrincipalResolver::class)]
class ApiTokenPrincipalResolverTest extends TestCase
{
    protected const string TOKEN = 'a-strong-random-token';

    protected const string OTHER_TOKEN = 'another-strong-random-token';

    protected MockObject $moduleConfigMock;
    protected MockObject $loggerServiceMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getEncryptionKey')->willReturn('a-secret-salt');
        $this->moduleConfigMock->method('getApiTokens')->willReturn([self::TOKEN => [], self::OTHER_TOKEN => []]);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }

    protected function sut(?ModuleConfig $moduleConfig = null): ApiTokenPrincipalResolver
    {
        return new ApiTokenPrincipalResolver(
            $moduleConfig ?? $this->moduleConfigMock,
            $this->loggerServiceMock,
        );
    }

    /**
     * Nothing stops an operator writing the token as its own display name, and the resulting audit
     * row would hold the bearer secret this whole class exists to keep out of it.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testIgnoresANameWhichIsTheTokenItself(): void
    {
        $this->moduleConfigMock->method('getApiTokenName')->willReturn(self::TOKEN);
        $this->loggerServiceMock->expects($this->once())->method('warning');

        $principal = $this->sut()->resolve(self::TOKEN);

        $this->assertStringNotContainsString(self::TOKEN, $principal);
        $this->assertMatchesRegularExpression('/^token:[0-9a-f]{16}$/', $principal);
    }

    /**
     * A name the token is buried in is no safer than one which is the token, and reads far more like
     * something an operator would write on purpose.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testIgnoresANameWhichMerelyCarriesTheToken(): void
    {
        $this->moduleConfigMock->method('getApiTokenName')
            ->willReturn(sprintf('HR system (%s)', self::TOKEN));
        $this->loggerServiceMock->expects($this->once())->method('warning');

        $this->assertStringNotContainsString(self::TOKEN, $this->sut()->resolve(self::TOKEN));
    }

    /**
     * A name is just as dangerous when the secret buried in it belongs to a different token, and that
     * token would authenticate perfectly well while leaking somebody else's.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testIgnoresANameCarryingSomeOtherConfiguredToken(): void
    {
        $this->moduleConfigMock->method('getApiTokenName')
            ->willReturn(sprintf('HR system, replaces %s', self::OTHER_TOKEN));
        $this->loggerServiceMock->expects($this->once())->method('warning');

        $this->assertStringNotContainsString(self::OTHER_TOKEN, $this->sut()->resolve(self::TOKEN));
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testUsesTheConfiguredName(): void
    {
        $this->moduleConfigMock->method('getApiTokenName')->willReturn('HR system');

        $this->assertSame('HR system', $this->sut()->resolve(self::TOKEN));
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testFallsBackToAFingerprintWhenThereIsNoName(): void
    {
        $this->moduleConfigMock->method('getApiTokenName')->willReturn(null);

        $this->assertMatchesRegularExpression('/^token:[0-9a-f]{16}$/', $this->sut()->resolve(self::TOKEN));
    }

    /**
     * An audit trail whose actor is the same for every caller records nothing worth having.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testFingerprintsDistinguishTokens(): void
    {
        $this->moduleConfigMock->method('getApiTokenName')->willReturn(null);

        $this->assertNotSame(
            $this->sut()->resolve(self::TOKEN),
            $this->sut()->resolve('a-different-token'),
        );
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testFingerprintsAreStable(): void
    {
        $this->moduleConfigMock->method('getApiTokenName')->willReturn(null);

        $this->assertSame($this->sut()->resolve(self::TOKEN), $this->sut()->resolve(self::TOKEN));
    }

    /**
     * The fingerprint goes into a database table. An unkeyed hash of a token an operator chose badly
     * could be confirmed by guessing it, which would make the audit trail an oracle for the very
     * secret it exists to keep out of the record.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testTheFingerprintIsKeyedRatherThanAPlainHash(): void
    {
        $this->moduleConfigMock->method('getApiTokenName')->willReturn(null);

        $otherConfig = $this->createMock(ModuleConfig::class);
        $otherConfig->method('getEncryptionKey')->willReturn('a-different-secret-salt');
        $otherConfig->method('getApiTokenName')->willReturn(null);

        $this->assertNotSame(
            $this->sut()->resolve(self::TOKEN),
            $this->sut($otherConfig)->resolve(self::TOKEN),
        );

        $this->assertStringNotContainsString(
            substr(hash('sha256', self::TOKEN), 0, 16),
            $this->sut()->resolve(self::TOKEN),
        );
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testNeverReturnsTheTokenItself(): void
    {
        $this->moduleConfigMock->method('getApiTokenName')->willReturn(null);

        $this->assertStringNotContainsString(self::TOKEN, $this->sut()->resolve(self::TOKEN));
    }

    /**
     * Naming the token is the way out of this, and the message says so.
     */
    public function testRefusesToFingerprintWithoutAnyKeyMaterial(): void
    {
        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('getEncryptionKey')->willReturn('');
        $moduleConfig->method('getApiTokenName')->willReturn(null);

        $this->expectException(ConfigurationError::class);

        $this->sut($moduleConfig)->resolve(self::TOKEN);
    }
}
