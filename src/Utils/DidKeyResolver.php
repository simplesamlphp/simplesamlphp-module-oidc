<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use Base64Url\Base64Url;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

/**
 * Utility class for resolving DID Key values to JWK format.
 * Based on the W3C DID Key specification: https://w3c-ccg.github.io/did-key-spec/
 */
class DidKeyResolver
{
    /**
     * Extract JWK from a did:key value.
     *
     * @param string $didKey The did:key value (e.g., did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbp7R1FUvzP1s9pLTKP21oYQNWMJFzgVGWYb5WmD3ngVmjMeTABs9MjYUaRfzTWg9dLdPw6o16UeakmtE7tHDMug3XgcJptPxRYuwFdVJXa6KAMUBhkmouMZisDJYMGbaGAp)
     * @return array The JWK representation of the key
     * @throws OidcServerException If the did:key format is invalid or unsupported
     */
    public function extractJwkFromDidKey(string $didKey): array
    {
        // Validate the did:key format
        if (!str_starts_with($didKey, 'did:key:')) {
            throw OidcServerException::serverError('Invalid did:key format. Must start with "did:key:"');
        }

        // Extract the multibase-encoded public key
        $multibaseKey = substr($didKey, 8); // Remove 'did:key:'
        
        // Check if it's a base58btc encoded key (starts with 'z')
        if (!str_starts_with($multibaseKey, 'z')) {
            throw OidcServerException::serverError('Unsupported multibase encoding. Only base58btc (z-prefixed) is currently supported.');
        }
        
        // Remove the multibase prefix ('z')
        $base58Key = substr($multibaseKey, 1);
        
        try {
            // Decode the base58 key
            $decodedKey = $this->base58Decode($base58Key);
            
            // The first byte is the multicodec identifier
            $multicodecIdentifier = ord($decodedKey[0]) * 256 + ord($decodedKey[1]);
            
            // Extract the actual key bytes (skip the multicodec bytes)
            $keyBytes = substr($decodedKey, 2);
            
            // Determine the key type based on the multicodec identifier
            // See: https://github.com/multiformats/multicodec/blob/master/table.csv
            switch ($multicodecIdentifier) {
                case 0xed01: // Ed25519 public key
                    return $this->createEd25519Jwk($keyBytes);
                case 0xec01: // X25519 public key
                    return $this->createX25519Jwk($keyBytes);
                case 0x1200: // Secp256k1 public key
                    return $this->createSecp256k1Jwk($keyBytes);
                case 0x1201: // P-256 (NIST) public key
                    return $this->createP256Jwk($keyBytes);
                case 0x1202: // P-384 (NIST) public key
                    return $this->createP384Jwk($keyBytes);
                case 0x1203: // P-521 (NIST) public key
                    return $this->createP521Jwk($keyBytes);
                default:
                    throw OidcServerException::serverError(sprintf('Unsupported key type with multicodec identifier: 0x%04x', $multicodecIdentifier));
            }
        } catch (\Exception $e) {
            throw OidcServerException::serverError('Error processing did:key: ' . $e->getMessage());
        }
    }
    
    /**
     * Decode a base58 encoded string.
     *
     * @param string $base58 The base58 encoded string
     * @return string The decoded binary data
     */
    private function base58Decode(string $base58): string
    {
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $base = strlen($alphabet);
        
        // Convert from base58 to base10
        $num = gmp_init(0);
        for ($i = 0; $i < strlen($base58); $i++) {
            $char = $base58[$i];
            $pos = strpos($alphabet, $char);
            if ($pos === false) {
                throw new \InvalidArgumentException("Invalid character in base58 string: $char");
            }
            $num = gmp_add(gmp_mul($num, $base), $pos);
        }
        
        // Convert from base10 to binary
        $result = '';
        while (gmp_cmp($num, 0) > 0) {
            list($num, $remainder) = gmp_div_qr($num, 256);
            $result = chr(gmp_intval($remainder)) . $result;
        }
        
        // Add leading zeros
        for ($i = 0; $i < strlen($base58) && $base58[$i] === '1'; $i++) {
            $result = "\0" . $result;
        }
        
        return $result;
    }
    
    /**
     * Create a JWK for an Ed25519 public key.
     *
     * @param string $keyBytes The raw key bytes
     * @return array The JWK representation
     */
    private function createEd25519Jwk(string $keyBytes): array
    {
        return [
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'x' => Base64Url::encode($keyBytes),
            'use' => 'sig',
        ];
    }
    
    /**
     * Create a JWK for an X25519 public key.
     *
     * @param string $keyBytes The raw key bytes
     * @return array The JWK representation
     */
    private function createX25519Jwk(string $keyBytes): array
    {
        return [
            'kty' => 'OKP',
            'crv' => 'X25519',
            'x' => Base64Url::encode($keyBytes),
            'use' => 'enc',
        ];
    }
    
    /**
     * Create a JWK for a Secp256k1 public key.
     *
     * @param string $keyBytes The raw key bytes
     * @return array The JWK representation
     */
    private function createSecp256k1Jwk(string $keyBytes): array
    {
        // For Secp256k1, we need to extract x and y coordinates from the compressed or uncompressed point
        $firstByte = ord($keyBytes[0]);
        
        if ($firstByte === 0x04 && strlen($keyBytes) === 65) {
            // Uncompressed point format (0x04 || x || y)
            $x = substr($keyBytes, 1, 32);
            $y = substr($keyBytes, 33, 32);
        } elseif (($firstByte === 0x02 || $firstByte === 0x03) && strlen($keyBytes) === 33) {
            // Compressed point format - would need to decompress
            // This is complex and requires secp256k1 library support
            throw OidcServerException::serverError('Compressed Secp256k1 keys are not currently supported');
        } else {
            throw OidcServerException::serverError('Invalid Secp256k1 public key format');
        }
        
        return [
            'kty' => 'EC',
            'crv' => 'secp256k1',
            'x' => Base64Url::encode($x),
            'y' => Base64Url::encode($y),
            'use' => 'sig',
        ];
    }
    
    /**
     * Create a JWK for a P-256 (NIST) public key.
     *
     * @param string $keyBytes The raw key bytes
     * @return array The JWK representation
     */
    private function createP256Jwk(string $keyBytes): array
    {
        // Similar to Secp256k1, we need to extract x and y coordinates
        $firstByte = ord($keyBytes[0]);
        
        if ($firstByte === 0x04 && strlen($keyBytes) === 65) {
            // Uncompressed point format (0x04 || x || y)
            $x = substr($keyBytes, 1, 32);
            $y = substr($keyBytes, 33, 32);
        } else {
            throw OidcServerException::serverError('Invalid P-256 public key format');
        }
        
        return [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => Base64Url::encode($x),
            'y' => Base64Url::encode($y),
            'use' => 'sig',
        ];
    }
    
    /**
     * Create a JWK for a P-384 (NIST) public key.
     *
     * @param string $keyBytes The raw key bytes
     * @return array The JWK representation
     */
    private function createP384Jwk(string $keyBytes): array
    {
        $firstByte = ord($keyBytes[0]);
        
        if ($firstByte === 0x04 && strlen($keyBytes) === 97) {
            // Uncompressed point format (0x04 || x || y)
            $x = substr($keyBytes, 1, 48);
            $y = substr($keyBytes, 49, 48);
        } else {
            throw OidcServerException::serverError('Invalid P-384 public key format');
        }
        
        return [
            'kty' => 'EC',
            'crv' => 'P-384',
            'x' => Base64Url::encode($x),
            'y' => Base64Url::encode($y),
            'use' => 'sig',
        ];
    }
    
    /**
     * Create a JWK for a P-521 (NIST) public key.
     *
     * @param string $keyBytes The raw key bytes
     * @return array The JWK representation
     */
    private function createP521Jwk(string $keyBytes): array
    {
        $firstByte = ord($keyBytes[0]);
        
        if ($firstByte === 0x04 && strlen($keyBytes) === 133) {
            // Uncompressed point format (0x04 || x || y)
            $x = substr($keyBytes, 1, 66);
            $y = substr($keyBytes, 67, 66);
        } else {
            throw OidcServerException::serverError('Invalid P-521 public key format');
        }
        
        return [
            'kty' => 'EC',
            'crv' => 'P-521',
            'x' => Base64Url::encode($x),
            'y' => Base64Url::encode($y),
            'use' => 'sig',
        ];
    }
}