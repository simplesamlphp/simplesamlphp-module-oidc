# Utility Classes

This directory contains various utility classes used throughout the module.

## DidKeyResolver

The `DidKeyResolver` class provides functionality to extract a JWK (JSON Web Key) from a "did:key" value according to the [W3C DID Key specification](https://w3c-ccg.github.io/did-key-spec/).

### Usage

```php
// Instantiate the resolver
$didKeyResolver = new DidKeyResolver();

// Extract JWK from a did:key value
$didKey = 'did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbp7R1FUvzP1s9pLTKP21oYQNWMJFzgVGWYb5WmD3ngVmjMeTABs9MjYUaRfzTWg9dLdPw6o16UeakmtE7tHDMug3XgcJptPxRYuwFdVJXa6KAMUBhkmouMZisDJYMGbaGAp';
$jwk = $didKeyResolver->extractJwkFromDidKey($didKey);

// Use the JWK for verification or other purposes
// ...
```

### Supported Key Types

The `DidKeyResolver` supports the following key types:

- Ed25519 (0xed01)
- X25519 (0xec01)
- Secp256k1 (0x1200)
- P-256 (NIST) (0x1201)
- P-384 (NIST) (0x1202)
- P-521 (NIST) (0x1203)

### Implementation Details

The `DidKeyResolver` implements the following steps to extract a JWK from a "did:key" value:

1. Validate the "did:key" format (must start with "did:key:")
2. Extract the multibase-encoded public key
3. Check if it's a base58btc encoded key (starts with 'z')
4. Decode the base58 key
5. Determine the key type based on the multicodec identifier
6. Extract the actual key bytes and create the appropriate JWK representation

For more information about the "did:key" format and the W3C DID Key specification, see the [official documentation](https://w3c-ccg.github.io/did-key-spec/).