<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Validators;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\OAuth2;
use SimpleSAML\OpenID\Serializers\JwsSerializerEnum;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\X509;
use SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\CertificateBuilder;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;

/**
 * A wallet provider's PKI and the Client Attestations and PoPs of one of its client instances, made when the tests
 * run so that nothing expires: a root, an issuing CA under it, and the attester's certificate under that, naming
 * the attester by a SAN URI and a SAN DNS name; an EC P-256 Client Instance Key; and the client registered to
 * trust that attester. Claims default to an attestation and PoP every check accepts at the time of the call.
 */
final readonly class ClientAttestationBuilder
{
    public const string ISSUER = 'https://op.example.org';

    public const string CLIENT_ID = 'wallet-a';

    public const string ATTESTER = 'https://provider-a.example.org';

    public const string ATTESTER_HOST = 'provider-a.example.org';

    public const string ROOT_SUBJECT = 'CN=Wallet Root CA';

    public const string ISSUING_CA_SUBJECT = 'CN=Wallet Issuing CA';

    public const string ATTESTER_SUBJECT = 'CN=Wallet Provider A,O=Example';


    public PrivateKeyInfo $rootKey;

    public string $rootDer;

    public PrivateKeyInfo $issuingCaKey;

    public string $issuingCaDer;

    public PrivateKeyInfo $attesterKey;

    public string $attesterDer;

    public JWK $instanceKey;

    protected OAuth2 $signer;

    protected X509 $x509;


    public function __construct()
    {
        $this->signer = new OAuth2(supportedAlgorithms: self::supportedAlgorithms());
        $this->x509 = new X509();

        $this->rootKey = CertificateBuilder::ecKey();
        $this->rootDer = CertificateBuilder::root($this->rootKey, self::ROOT_SUBJECT);

        [$this->issuingCaKey, $this->issuingCaDer] = $this->issuingCa();
        [$this->attesterKey, $this->attesterDer] = $this->attesterCertificate($this->issuingCaKey);

        $this->instanceKey = JWKFactory::createECKey('P-256');
    }


    /**
     * An issuing CA under the root (or under the given issuer), with a key of its own.
     *
     * @return array{\SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo, string}
     */
    public function issuingCa(
        string $subject = self::ISSUING_CA_SUBJECT,
        ?PrivateKeyInfo $issuerKey = null,
        string $issuer = self::ROOT_SUBJECT,
    ): array {
        $key = CertificateBuilder::ecKey();

        return [
            $key,
            CertificateBuilder::certificate(
                $subject,
                $key,
                $issuer,
                $issuerKey ?? $this->rootKey,
                CertificateBuilder::caExtensions(),
                '-1 hour',
                '+1 year',
            ),
        ];
    }


    /**
     * An attester's certificate issued by the given CA, with a key of its own.
     *
     * @return array{\SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo, string}
     */
    public function attesterCertificate(
        PrivateKeyInfo $issuingCaKey,
        string $subject = self::ATTESTER_SUBJECT,
        string $issuer = self::ISSUING_CA_SUBJECT,
        string $uri = self::ATTESTER,
        string $host = self::ATTESTER_HOST,
        string $notAfter = '+1 day',
    ): array {
        $key = CertificateBuilder::ecKey();

        return [
            $key,
            CertificateBuilder::certificate(
                $subject,
                $key,
                $issuer,
                $issuingCaKey,
                CertificateBuilder::leafExtensions([$uri], [$host]),
                '-1 hour',
                $notAfter,
            ),
        ];
    }


    /**
     * The algorithms the tokens are signed with, and which an OAuth2 facade verifying them has to know.
     */
    public static function supportedAlgorithms(): SupportedAlgorithms
    {
        return new SupportedAlgorithms(
            new SignatureAlgorithmBag(SignatureAlgorithmEnum::ES256, SignatureAlgorithmEnum::ES384),
        );
    }


    public function publicKeySha256(string $der): string
    {
        return $this->x509->certificateFactory()->fromDer($der)->getPublicKeySha256();
    }


    public static function jwk(PrivateKeyInfo $key): JWK
    {
        return JWKFactory::createFromKey(CertificateBuilder::privateKeyPem($key));
    }


    /**
     * The trust as a client record keeps it, trusting this attester under this issuing CA, with the given members
     * replaced.
     *
     * @param array<string,mixed> $replacements
     * @return array<string,mixed>
     */
    public function trust(array $replacements = []): array
    {
        return [
            'attester' => self::ATTESTER,
            'issuing_ca_public_key_sha256' => $this->publicKeySha256($this->issuingCaDer),
            'attester_identity' => ['type' => 'san_uri', 'value' => self::ATTESTER],
            'trust_anchors' => CertificateBuilder::pem($this->rootDer),
            ...$replacements,
        ];
    }


    /**
     * A client registered for attestation-based client authentication, trusting this attester, unless told
     * otherwise.
     *
     * @param array<string,mixed>|null $trust Null for a client without trust.
     */
    public function client(
        ?array $trust = [],
        ?string $tokenEndpointAuthMethod = 'attest_jwt_client_auth',
        string $clientId = self::CLIENT_ID,
    ): ClientEntity {
        $extraMetadata = [];
        if ($tokenEndpointAuthMethod !== null) {
            $extraMetadata['token_endpoint_auth_method'] = $tokenEndpointAuthMethod;
        }
        if ($trust !== null) {
            $extraMetadata[ClientEntity::KEY_CLIENT_ATTESTATION] = $trust === [] ? $this->trust() : $trust;
        }

        return new ClientEntity(
            identifier: $clientId,
            secret: 'unused-secret',
            name: 'Wallet A',
            description: 'A wallet authenticating by attestation',
            redirectUri: ['https://wallet-a.example.org/cb'],
            scopes: ['openid'],
            isEnabled: true,
            isConfidential: true,
            extraMetadata: $extraMetadata,
        );
    }


    /**
     * A Client Attestation signed by the attester, its x5c the attester's certificate and the issuing CA's, unless
     * the arguments say otherwise. A claim or header parameter given as null is left out. Signed as given, so that
     * attestations the library's factory would refuse to sign can be made too.
     *
     * @param array<string,mixed> $claims
     * @param array<string,mixed> $header
     */
    public function attestation(
        array $claims = [],
        array $header = [],
        ?JWK $signingKey = null,
        SignatureAlgorithmEnum $algorithm = SignatureAlgorithmEnum::ES256,
        ?JWK $instanceKey = null,
    ): string {
        $now = time();

        $payload = array_filter(
            [
                'iss' => self::ATTESTER,
                'sub' => self::CLIENT_ID,
                'iat' => $now,
                'nbf' => $now,
                'exp' => $now + 300,
                'cnf' => ['jwk' => ($instanceKey ?? $this->instanceKey)->toPublic()->all()],
                ...$claims,
            ],
            static fn(mixed $value): bool => $value !== null,
        );

        $header = array_filter(
            [
                'alg' => $algorithm->value,
                'typ' => 'oauth-client-attestation+jwt',
                'x5c' => [base64_encode($this->attesterDer), base64_encode($this->issuingCaDer)],
                ...$header,
            ],
            static fn(mixed $value): bool => $value !== null,
        );

        return $this->rawJws($payload, $header, $signingKey ?? self::jwk($this->attesterKey), $algorithm);
    }


    /**
     * A Client Attestation PoP signed with the Client Instance Key, unless told otherwise. A claim given as null is
     * left out. Signed as given, as attestation() is.
     *
     * @param array<string,mixed> $claims
     */
    public function pop(
        array $claims = [],
        ?JWK $signingKey = null,
        SignatureAlgorithmEnum $algorithm = SignatureAlgorithmEnum::ES256,
    ): string {
        $payload = array_filter(
            [
                'iss' => self::CLIENT_ID,
                'aud' => self::ISSUER,
                'jti' => bin2hex(random_bytes(16)),
                'iat' => time(),
                ...$claims,
            ],
            static fn(mixed $value): bool => $value !== null,
        );

        return $this->rawJws(
            $payload,
            ['alg' => $algorithm->value, 'typ' => 'oauth-client-attestation-pop+jwt'],
            $signingKey ?? $this->instanceKey,
            $algorithm,
        );
    }


    /**
     * A JWS as given, which the library's factories would not always sign: they refuse a token which fails the
     * checks the library makes when it parses one.
     *
     * @param array<string,mixed> $payload
     * @param array<string,mixed> $header
     */
    public function rawJws(
        array $payload,
        array $header,
        JWK $signingKey,
        SignatureAlgorithmEnum $algorithm = SignatureAlgorithmEnum::ES256,
    ): string {
        return $this->signer->jwsSerializerManagerDecorator()->serialize(
            JwsSerializerEnum::Compact->value,
            $this->signer->jwsDecoratorBuilder()->fromData(
                new JwkDecorator($signingKey),
                $algorithm,
                $payload,
                $header,
            ),
        );
    }
}
