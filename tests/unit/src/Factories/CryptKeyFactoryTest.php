<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use Closure;
use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Factories\CryptKeyFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;

/**
 * The factory behind the protocol signing keys.
 *
 * `routing/services/services.yml` names `buildPrivateKey` and `buildPublicKey` as the factories of the
 * `oidc.key.private` and `oidc.key.public` services, League CryptKeys; the AuthorizationServerFactory and the
 * TokenResponseFactory take the private one, and nothing under `src/` takes the public one. What the factory
 * decides is which key pair that is: the first of the configured protocol signature key pairs, whatever it is
 * keyed by and however many follow, handed to the configuration for validation, or refused as a configuration
 * error when it is not an array at all. Each key is then read from its file: the private key with the
 * configured password and with League's permission check on, which is a notice on a key file readable by
 * others; the public key with neither.
 *
 * The key files are copies of the test key pair in the temporary directory, since that check reads the file
 * mode, and the mode of a checked-out file is whatever the umask made it.
 */
#[CoversClass(CryptKeyFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class CryptKeyFactoryTest extends TestCase
{
    /** The first configured key pair as written; the configuration validates it into the shape the factory reads. */
    protected const array FIRST_KEY_PAIR = [
        ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::RS256,
        ModuleConfig::KEY_PRIVATE_KEY_FILENAME => 'oidc_module.key',
        ModuleConfig::KEY_PUBLIC_KEY_FILENAME => 'oidc_module.crt',
    ];

    /** A second pair, which the factory passes over: the configuration is never asked to validate it. */
    protected const array SECOND_KEY_PAIR = [
        ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::ES256,
        ModuleConfig::KEY_PRIVATE_KEY_FILENAME => 'other.key',
        ModuleConfig::KEY_PUBLIC_KEY_FILENAME => 'other.crt',
    ];

    protected const string PRIVATE_KEY_PASSWORD = 'private-key-password';


    protected MockObject $moduleConfigMock;

    protected string $privateKeyPath;

    protected string $publicKeyPath;


    protected function setUp(): void
    {
        $this->privateKeyPath = $this->copyOfTheTestKeyFile('oidc_module.key', 0600);
        $this->publicKeyPath = $this->copyOfTheTestKeyFile('oidc_module.crt', 0644);

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
    }


    protected function tearDown(): void
    {
        foreach ([$this->privateKeyPath, $this->publicKeyPath] as $path) {
            if (is_file($path)) {
                unlink($path);
            }
        }
    }


    /**
     * A copy of one of the test key files, with the mode League's permission check will read.
     */
    protected function copyOfTheTestKeyFile(string $name, int $mode): string
    {
        $path = tempnam(sys_get_temp_dir(), 'oidc-module-' . $name . '-');

        if ($path === false || !copy(dirname(__DIR__, 3) . '/cert/' . $name, $path) || !chmod($path, $mode)) {
            throw new RuntimeException('Could not set up a copy of the test key file ' . $name . '.');
        }

        return $path;
    }


    /**
     * The first pair is configured under a name, not at index zero, and a second follows it.
     */
    protected function sut(mixed $firstKeyPair = self::FIRST_KEY_PAIR): CryptKeyFactory
    {
        $this->moduleConfigMock->method('getProtocolSignatureKeyPairs')
            ->willReturn(['default' => $firstKeyPair, 'next' => self::SECOND_KEY_PAIR]);

        return new CryptKeyFactory($this->moduleConfigMock);
    }


    /**
     * The configuration validates the pair it is handed, once per key built, and answers with the absolute
     * file paths and the password. Only the first pair may be handed to it.
     */
    protected function expectTheFirstKeyPairValidated(?string $privateKeyPassword = null, int $builds = 1): void
    {
        $this->moduleConfigMock->expects($this->exactly($builds))->method('getValidatedSignatureKeyPairArray')
            ->with($this->identicalTo(self::FIRST_KEY_PAIR))
            ->willReturn([
                ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::RS256,
                ModuleConfig::KEY_PRIVATE_KEY_FILENAME => $this->privateKeyPath,
                ModuleConfig::KEY_PUBLIC_KEY_FILENAME => $this->publicKeyPath,
                ModuleConfig::KEY_PRIVATE_KEY_PASSWORD => $privateKeyPassword,
                ModuleConfig::KEY_KEY_ID => null,
            ]);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(CryptKeyFactory::class, $this->sut());
    }


    /**
     * The private key is read from the first pair's private key file, with the password the pair configures,
     * which may be none.
     */
    #[DataProvider('privateKeyPasswordProvider')]
    public function testBuildsThePrivateKeyFromTheFirstConfiguredKeyPair(?string $privateKeyPassword): void
    {
        $this->expectTheFirstKeyPairValidated($privateKeyPassword);

        $privateKey = $this->sut()->buildPrivateKey();

        $this->assertSame('file://' . $this->privateKeyPath, $privateKey->getKeyPath());
        $this->assertStringEqualsFile($this->privateKeyPath, $privateKey->getKeyContents());
        $this->assertSame($privateKeyPassword, $privateKey->getPassPhrase());
    }


    public static function privateKeyPasswordProvider(): array
    {
        return [
            'with a password' => [self::PRIVATE_KEY_PASSWORD],
            'without one' => [null],
        ];
    }


    /**
     * The public key is read from the first pair's public key file; the pair's password is the private key's
     * and is not given to it.
     */
    public function testBuildsThePublicKeyFromTheFirstConfiguredKeyPair(): void
    {
        $this->expectTheFirstKeyPairValidated(self::PRIVATE_KEY_PASSWORD);

        $publicKey = $this->sut()->buildPublicKey();

        $this->assertSame('file://' . $this->publicKeyPath, $publicKey->getKeyPath());
        $this->assertStringEqualsFile($this->publicKeyPath, $publicKey->getKeyContents());
        $this->assertNull($publicKey->getPassPhrase());
    }


    /**
     * A first pair which is not an array is refused before the configuration is asked to validate anything;
     * the configuration's own check would have refused it too, with a message of its own, but never gets it.
     */
    #[DataProvider('builderProvider')]
    public function testRefusesAKeyPairsConfigurationWhoseFirstPairIsNotAnArray(Closure $build): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getValidatedSignatureKeyPairArray');
        $sut = $this->sut(firstKeyPair: 'oidc_module.key');

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('Invalid protocol signature key pairs config.');

        $build($sut);
    }


    public static function builderProvider(): array
    {
        return [
            'the private key' => [static fn(CryptKeyFactory $sut): CryptKey => $sut->buildPrivateKey()],
            'the public key' => [static fn(CryptKeyFactory $sut): CryptKey => $sut->buildPublicKey()],
        ];
    }


    /**
     * League's permission check is on for the private key alone: on a key file readable by others it is a
     * notice naming the file. The public key file, readable by others as such a file is, draws none.
     */
    public function testHasThePermissionsOfThePrivateKeyFileCheckedButNotThePublicKeyFiles(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('League leaves the permission check out on Windows.');
        }

        $this->assertTrue(chmod($this->privateKeyPath, 0644));
        $this->expectTheFirstKeyPairValidated(builds: 2);
        /** @var list<array{int, string}> $notices */
        $notices = [];
        set_error_handler(
            static function (int $level, string $message) use (&$notices): bool {
                $notices[] = [$level, $message];

                return true;
            },
        );

        try {
            $sut = $this->sut();
            $sut->buildPrivateKey();
            $sut->buildPublicKey();
        } finally {
            restore_error_handler();
        }

        $this->assertCount(1, $notices);
        $this->assertSame(E_USER_NOTICE, $notices[0][0]);
        $this->assertStringContainsString('file://' . $this->privateKeyPath, $notices[0][1]);
    }
}
