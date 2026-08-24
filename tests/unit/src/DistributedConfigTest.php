<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;

/**
 * Keeps the configuration file that ships with the module in step with the installation guide.
 *
 * Nothing else in the suite reads `config/module_oidc.php.dist`: both `tests/config/module_oidc.php`
 * and `docker/ssp/module_oidc.php` declare their own key pairs. The distributed file is therefore
 * exercised for the first time by whoever installs the module, which is how it came to activate an
 * ES256 entry pointing at EC key files that the guide creates only in an optional section.
 */
#[CoversNothing]
#[AllowMockObjectsWithoutExpectations]
class DistributedConfigTest extends TestCase
{
    /** @var array<string,mixed> */
    protected array $distributedConfig;

    protected string $installationGuide;


    protected function setUp(): void
    {
        $repositoryRoot = dirname(__DIR__, 3);

        // The distributed configuration follows the SimpleSAMLphp convention of assigning $config
        // instead of returning it, so include it for that side effect and pick the variable up.
        require $repositoryRoot . '/config/module_oidc.php.dist';
        /** @var array<string,mixed> $config */
        $this->distributedConfig = $config;

        $this->installationGuide = (string)file_get_contents(
            $repositoryRoot . '/docs/2-oidc-installation.md',
        );
    }


    /**
     * The protocol key pairs are resolved before any JWS can be signed, and all of them are, so an
     * entry naming a key file that a fresh installation does not have stops the module from signing
     * altogether rather than just dropping its own algorithm. Only the RSA pair that the guide
     * creates in its baseline instructions may therefore ship active; anything else belongs in the
     * file commented out, next to the key generation it needs.
     */
    public function testDistributedProtocolKeyPairsMatchTheBaselineInstallation(): void
    {
        /** @var array<array<string,mixed>> $keyPairs */
        $keyPairs = $this->distributedConfig[ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS];

        $this->assertCount(
            1,
            $keyPairs,
            'The distributed configuration must activate exactly the one protocol key pair that the ' .
            'baseline installation instructions create. Ship additional algorithms commented out.',
        );

        $keyPair = $keyPairs[0];

        $this->assertSame(SignatureAlgorithmEnum::RS256, $keyPair[ModuleConfig::KEY_ALGORITHM]);
        $this->assertSame(
            'oidc_module_connect_rsa_01.key',
            $keyPair[ModuleConfig::KEY_PRIVATE_KEY_FILENAME],
        );
        $this->assertSame(
            'oidc_module_connect_rsa_01.pub',
            $keyPair[ModuleConfig::KEY_PUBLIC_KEY_FILENAME],
        );
    }

    /**
     * Catches the milder version of the same drift: an active entry naming a key file that the guide
     * never tells anyone to create, in either direction, such as a renamed or mistyped filename.
     */
    #[DataProvider('keyPairOptionProvider')]
    public function testActiveKeyFilenamesAreCreatedByTheInstallationGuide(string $option): void
    {
        /** @var array<array<string,mixed>> $keyPairs */
        $keyPairs = $this->distributedConfig[$option];

        foreach ($keyPairs as $keyPair) {
            foreach (
                [ModuleConfig::KEY_PRIVATE_KEY_FILENAME, ModuleConfig::KEY_PUBLIC_KEY_FILENAME] as $filenameKey
            ) {
                /** @var string $filename */
                $filename = $keyPair[$filenameKey];

                $this->assertStringContainsString(
                    $filename,
                    $this->installationGuide,
                    sprintf(
                        'Option %s activates key file %s, which docs/2-oidc-installation.md does not ' .
                        'tell anyone to create.',
                        $option,
                        $filename,
                    ),
                );
            }
        }
    }


    /**
     * @return array<string,array{string}>
     */
    public static function keyPairOptionProvider(): array
    {
        return [
            'protocol' => [ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS],
            'federation' => [ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS],
            'vci' => [ModuleConfig::OPTION_VCI_SIGNATURE_KEY_PAIRS],
        ];
    }
}
