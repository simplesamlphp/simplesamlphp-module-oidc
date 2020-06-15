<?php


namespace SimpleSAML\Modules\OpenIDConnect\Utils;


class FingerprintGenerator
{
    /**
     * Generate a fingerprint (hash) for a provided file.
     *
     * @param string $path Location of file
     * @param string $algo One of the supported algorithms (see hash_algos() function)
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function forFile($path, $algo = 'md5')
    {
        $fingerprint = hash_file($algo, $path);

        if (false === $fingerprint) {
            throw new \InvalidArgumentException('Could not create a fingerprint for provided file using' .
                ' provided algorithm.');
        }

        return $fingerprint;
    }

    /**
     * Generate a fingerprint (hash) for a provided string.
     *
     * @param string $content Content for which to create a fingerprint
     * @param string $algo One of the supported algorithms (see hash_algos() function)
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function forString($content, $algo = 'md5')
    {
        $fingerprint = hash($algo, $content);

        if (false === $fingerprint) {
            throw new \InvalidArgumentException('Could not create a fingerprint for provided content using' .
                ' provided algorithm.');
        }

        return $fingerprint;
    }
}