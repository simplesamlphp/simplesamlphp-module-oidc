<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials;

use Jose\Component\KeyManagement\JWKFactory;
use RuntimeException;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\ECDSAWithSHA256AlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\OneAsymmetricKey;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Extension\BasicConstraintsExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extension\SubjectAlternativeNameExtension;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use SpomkyLabs\Pki\X509\GeneralName\DNSName;
use SpomkyLabs\Pki\X509\GeneralName\GeneralNames;
use SpomkyLabs\Pki\X509\GeneralName\UniformResourceIdentifier;

/**
 * EC P-256 keys and certificates for the tests of issuer certificate chains, made when the tests run, so that no
 * fixture expires. Built with pki-framework (which the openid library reads certificates with), since PHP's
 * openssl_csr_sign() sets neither a validity period in the past nor the extensions a CA needs. A trimmed copy of the
 * openid library's own test builder, which its distribution does not ship.
 */
final class CertificateBuilder
{
    public static function ecKey(): PrivateKeyInfo
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        if ($key === false || !openssl_pkey_export($key, $pem)) {
            throw new RuntimeException('Unable to generate a key.');
        }

        $oneAsymmetricKey = OneAsymmetricKey::fromPEM(PEM::fromString((string)$pem));

        return PrivateKeyInfo::create($oneAsymmetricKey->algorithmIdentifier(), $oneAsymmetricKey->privateKeyData());
    }


    /**
     * A certificate in DER, signed with the issuer's key (ECDSA with SHA-256).
     *
     * @param list<\SpomkyLabs\Pki\X509\Certificate\Extension\Extension> $extensions
     */
    public static function certificate(
        string $subject,
        PrivateKeyInfo $subjectKey,
        string $issuer,
        PrivateKeyInfo $issuerKey,
        array $extensions = [],
        string $notBefore = '-1 hour',
        string $notAfter = '+1 day',
    ): string {
        $tbsCertificate = TBSCertificate::create(
            Name::fromString($subject),
            $subjectKey->publicKeyInfo(),
            Name::fromString($issuer),
            Validity::fromStrings($notBefore, $notAfter),
        );

        if ($extensions !== []) {
            $tbsCertificate = $tbsCertificate->withAdditionalExtensions(...$extensions);
        }

        return $tbsCertificate->sign(ECDSAWithSHA256AlgorithmIdentifier::create(), $issuerKey)->toDER();
    }


    /**
     * A self-signed CA certificate, for a trust anchor.
     */
    public static function root(
        PrivateKeyInfo $key,
        string $subject = 'CN=Test Root CA',
        string $notAfter = '+1 year',
    ): string {
        return self::certificate($subject, $key, $subject, $key, self::caExtensions(), '-1 hour', $notAfter);
    }


    /**
     * Basic constraints marking a CA, and a key usage for signing certificates and CRLs, both critical.
     *
     * @return list<\SpomkyLabs\Pki\X509\Certificate\Extension\Extension>
     */
    public static function caExtensions(): array
    {
        return [
            BasicConstraintsExtension::create(true, true),
            KeyUsageExtension::create(true, KeyUsageExtension::KEY_CERT_SIGN | KeyUsageExtension::CRL_SIGN),
        ];
    }


    /**
     * Basic constraints marking an end entity, a key usage for digital signatures, and the given subject
     * alternative names.
     *
     * @param list<string> $uris
     * @param list<string> $dnsNames
     * @return list<\SpomkyLabs\Pki\X509\Certificate\Extension\Extension>
     */
    public static function leafExtensions(array $uris = [], array $dnsNames = []): array
    {
        $extensions = [
            BasicConstraintsExtension::create(true, false),
            KeyUsageExtension::create(true, KeyUsageExtension::DIGITAL_SIGNATURE),
        ];

        $names = [
            ...array_map(UniformResourceIdentifier::create(...), $uris),
            ...array_map(DNSName::create(...), $dnsNames),
        ];

        if ($names !== []) {
            $extensions[] = SubjectAlternativeNameExtension::create(false, GeneralNames::create(...$names));
        }

        return $extensions;
    }


    public static function pem(string ...$ders): string
    {
        return implode('', array_map(
            static fn(string $der): string => "-----BEGIN CERTIFICATE-----\n" .
                chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n",
            $ders,
        ));
    }


    public static function privateKeyPem(PrivateKeyInfo $key): string
    {
        return $key->toPEM()->string();
    }


    public static function publicKeyPem(PrivateKeyInfo $key): string
    {
        return $key->publicKeyInfo()->toPEM()->string();
    }


    /**
     * @return array<string,mixed>
     */
    public static function publicJwk(PrivateKeyInfo $key): array
    {
        return JWKFactory::createFromKey(self::publicKeyPem($key))->all();
    }
}
