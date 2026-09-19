<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;
use ValueError;

/**
 * Two static hashing helpers, MD5 unless told otherwise. Nothing in `src/` calls either today; they are
 * pinned as they stand, against digests written out rather than recomputed, so a change of the default
 * algorithm would show.
 */
#[CoversClass(FingerprintGenerator::class)]
class FingerprintGeneratorTest extends TestCase
{
    protected const string CONTENT = 'hello';

    protected const string MD5_OF_CONTENT = '5d41402abc4b2a76b9719d911017c592';

    protected const string SHA256_OF_CONTENT = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';


    protected string $path;


    protected function setUp(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'oidc-fingerprint-');

        if ($path === false || file_put_contents($path, self::CONTENT) !== strlen(self::CONTENT)) {
            throw new RuntimeException('Could not set up the file to fingerprint.');
        }

        $this->path = $path;
    }


    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }


    public function testFingerprintsAStringWithMd5UnlessToldOtherwise(): void
    {
        $this->assertSame(self::MD5_OF_CONTENT, FingerprintGenerator::forString(self::CONTENT));
        $this->assertSame(self::SHA256_OF_CONTENT, FingerprintGenerator::forString(self::CONTENT, 'sha256'));
    }


    public function testFingerprintsAFilesContentsWithMd5UnlessToldOtherwise(): void
    {
        $this->assertSame(self::MD5_OF_CONTENT, FingerprintGenerator::forFile($this->path));
        $this->assertSame(self::SHA256_OF_CONTENT, FingerprintGenerator::forFile($this->path, 'sha256'));
    }


    /**
     * A file which cannot be read is the one way `hash_file()` answers false rather than throwing, and it
     * does so with a warning, which the test takes off PHPUnit's hands and checks for.
     */
    public function testRefusesToFingerprintAFileItCannotRead(): void
    {
        $warnings = [];
        set_error_handler(static function (int $level, string $message) use (&$warnings): bool {
            $warnings[] = [$level, $message];

            return true;
        });

        try {
            $this->expectException(InvalidArgumentException::class);
            $this->expectExceptionMessage('Could not create a fingerprint for provided file using provided algorithm.');

            FingerprintGenerator::forFile($this->path . '-missing');
        } finally {
            restore_error_handler();

            $this->assertCount(1, $warnings);
            $this->assertSame(E_WARNING, $warnings[0][0]);
            $this->assertStringContainsString('Failed to open stream', $warnings[0][1]);
        }
    }


    /**
     * An unknown algorithm is not the helper's refusal but PHP's own error, for a string and a file alike.
     */
    public function testAnUnknownAlgorithmIsPhpsOwnErrorForAString(): void
    {
        $this->expectException(ValueError::class);

        FingerprintGenerator::forString(self::CONTENT, 'md4x');
    }


    public function testAnUnknownAlgorithmIsPhpsOwnErrorForAFile(): void
    {
        $this->expectException(ValueError::class);

        FingerprintGenerator::forFile($this->path, 'md4x');
    }
}
