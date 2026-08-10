<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Registration;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Registration\ClientMetadataValidator;
use SimpleSAML\OpenID\Network\DestinationPolicy;

#[CoversClass(ClientMetadataValidator::class)]
class ClientMetadataValidatorTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    /**
     * Mocked rather than real, so that no test here performs a DNS lookup for a destination in its
     * metadata. What the policy decides is exercised in the library's own tests; what matters here is
     * that a refusal becomes an invalid_client_metadata error naming the offending claim.
     */
    protected MockObject $destinationPolicyMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        // Default: impersonation protection on.
        $this->moduleConfigMock->method('getDcrImpersonationProtectionEnabled')->willReturn(true);
        // Default: the OP advertises a single supported ACR.
        $this->moduleConfigMock->method('getAcrValuesSupported')->willReturn(['urn:mace:incommon:iap:silver']);
        $this->moduleConfigMock->method('getSupportedResponseTypes')
            ->willReturn(['code', 'id_token', 'id_token token']);
        $this->moduleConfigMock->method('getSupportedGrantTypes')
            ->willReturn(['authorization_code', 'implicit', 'refresh_token']);
        $this->moduleConfigMock->method('getSupportedTokenEndpointAuthMethods')
            ->willReturn(['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none']);

        $this->destinationPolicyMock = $this->createMock(DestinationPolicy::class);
        // Default: every destination is permitted, so the existing cases keep testing what they were
        // written to test. The cases that care override this.
        $this->destinationPolicyMock->method('isUriAllowed')->willReturn(true);
    }

    protected function sut(): ClientMetadataValidator
    {
        return new ClientMetadataValidator($this->moduleConfigMock, $this->destinationPolicyMock);
    }

    /**
     * Assert that validating the given metadata is rejected with the expected OAuth error code and a hint
     * containing the given substring.
     */
    protected function assertRejected(
        array $metadata,
        string $expectedErrorType,
        string $expectedHintSubstring,
        bool $isCallerAuthenticated = false,
    ): void {
        try {
            $this->sut()->validate($metadata, $isCallerAuthenticated);
            $this->fail('Expected OidcServerException was not thrown.');
        } catch (OidcServerException $exception) {
            $this->assertSame($expectedErrorType, $exception->getErrorType());
            $this->assertStringContainsString($expectedHintSubstring, (string)$exception->getHint());
        }
    }

    public function testValidMetadataPasses(): void
    {
        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'client_name' => 'Example',
            'logo_uri' => 'https://client.example.org/logo.png',
            'policy_uri' => 'https://client.example.org/policy',
            'tos_uri' => 'https://client.example.org/tos',
            'client_uri' => 'https://marketing.example.net/',
            'contacts' => ['admin@example.org'],
            'application_type' => 'web',
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testNativeRedirectUriIsAllowed(): void
    {
        $metadata = ['redirect_uris' => ['com.example.app:/callback']];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testMissingRedirectUrisIsRejected(): void
    {
        $this->assertRejected(['client_name' => 'Example'], 'invalid_redirect_uri', 'redirect_uris is required');
    }

    public function testEmptyRedirectUrisIsRejected(): void
    {
        $this->assertRejected(['redirect_uris' => []], 'invalid_redirect_uri', 'redirect_uris is required');
    }

    public function testRedirectUriWithoutSchemeIsRejected(): void
    {
        $this->assertRejected(['redirect_uris' => ['not-a-uri']], 'invalid_redirect_uri', 'invalid');
    }

    public function testInvalidLogoUriIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'logo_uri' => 'not a url'],
            'invalid_client_metadata',
            'logo_uri',
        );
    }

    public function testContactsMustBeArray(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'contacts' => 'admin@example.org'],
            'invalid_client_metadata',
            'contacts',
        );
    }

    public function testInvalidApplicationTypeIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'application_type' => 'desktop'],
            'invalid_client_metadata',
            'application_type',
        );
    }

    public function testValidRequestUrisPass(): void
    {
        // https URIs, including one with a fragment (OIDC Core allows a content-hash fragment on request_uri).
        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'request_uris' => [
                'https://client.example.org/request-object',
                'https://client.example.org/request-object#sha256hash',
            ],
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testRequestUrisMustBeArray(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'request_uris' => 'https://client.example.org/ro'],
            'invalid_client_metadata',
            'request_uris must be an array',
        );
    }

    public function testNonHttpsRequestUriIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'request_uris' => ['http://client.example.org/ro']],
            'invalid_client_metadata',
            'request_uris',
        );
    }

    public function testSubjectTypePublicIsAccepted(): void
    {
        $metadata = ['redirect_uris' => ['https://client.example.org/cb'], 'subject_type' => 'public'];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testPairwiseSubjectTypeIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'subject_type' => 'pairwise'],
            'invalid_client_metadata',
            'subject_type',
        );
    }

    /**
     * @dataProvider unsupportedFeatureMetadataProvider
     */
    public function testUnsupportedFeatureMetadataIsRejected(string $field, mixed $value): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], $field => $value],
            'invalid_client_metadata',
            'Unsupported metadata',
        );
    }

    public static function unsupportedFeatureMetadataProvider(): array
    {
        return [
            'sector_identifier_uri' => ['sector_identifier_uri', 'https://client.example.org/sector'],
            'userinfo_signed_response_alg' => ['userinfo_signed_response_alg', 'RS256'],
            'userinfo_encrypted_response_alg' => ['userinfo_encrypted_response_alg', 'RSA-OAEP'],
            'id_token_encrypted_response_alg' => ['id_token_encrypted_response_alg', 'RSA-OAEP'],
            'request_object_encryption_alg' => ['request_object_encryption_alg', 'RSA-OAEP'],
            'frontchannel_logout_uri' => ['frontchannel_logout_uri', 'https://client.example.org/fclo'],
            'frontchannel_logout_session_required' => ['frontchannel_logout_session_required', true],
        ];
    }

    public function testValidAdditionalMetadataPasses(): void
    {
        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'default_max_age' => 600,
            'require_auth_time' => true,
            'default_acr_values' => ['urn:mace:incommon:iap:silver'],
            'initiate_login_uri' => 'https://client.example.org/initiate',
            'software_id' => 'example-suite',
            'software_version' => '1.2.3',
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testNegativeDefaultMaxAgeIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'default_max_age' => -5],
            'invalid_client_metadata',
            'default_max_age',
        );
    }

    public function testNonBooleanRequireAuthTimeIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'require_auth_time' => 'yes'],
            'invalid_client_metadata',
            'require_auth_time',
        );
    }

    public function testNonArrayDefaultAcrValuesIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'default_acr_values' => 'silver'],
            'invalid_client_metadata',
            'default_acr_values',
        );
    }

    public function testUnsupportedGrantTypeIsRejected(): void
    {
        $this->assertRejected(
            [
                'redirect_uris' => ['https://client.example.org/cb'],
                'grant_types' => ['authorization_code', 'client_credentials'],
            ],
            'invalid_client_metadata',
            'grant_types',
        );
    }

    public function testUnsupportedResponseTypeIsRejected(): void
    {
        $this->assertRejected(
            [
                'redirect_uris' => ['https://client.example.org/cb'],
                'response_types' => ['code id_token token'],
            ],
            'invalid_client_metadata',
            'response_types',
        );
    }

    public function testUnsupportedTokenEndpointAuthMethodIsRejected(): void
    {
        $this->assertRejected(
            [
                'redirect_uris' => ['https://client.example.org/cb'],
                'token_endpoint_auth_method' => 'tls_client_auth',
            ],
            'invalid_client_metadata',
            'token_endpoint_auth_method',
        );
    }

    public function testSupportedGrantResponseAndAuthMethodArePassedThrough(): void
    {
        // 'none' (public client) and the implicit response/grant types are supported and must be accepted.
        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'grant_types' => ['authorization_code', 'implicit', 'refresh_token'],
            'response_types' => ['code', 'id_token', 'id_token token'],
            'token_endpoint_auth_method' => 'none',
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testUnsupportedDefaultAcrValueIsRejected(): void
    {
        $this->assertRejected(
            [
                'redirect_uris' => ['https://client.example.org/cb'],
                'default_acr_values' => ['urn:mace:incommon:iap:silver', 'urn:not:supported'],
            ],
            'invalid_client_metadata',
            'default_acr_values',
        );
    }

    public function testRedirectUriWithEmptyFragmentIsRejected(): void
    {
        // A trailing '#' is an (empty) fragment component, which OIDC Core 3.1.2.1 forbids.
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb#']],
            'invalid_redirect_uri',
            'fragment',
        );
    }

    public function testRedirectUriWithEncodedHashIsAllowed(): void
    {
        // A percent-encoded '%23' in the path is a literal '#', not a fragment delimiter.
        $metadata = ['redirect_uris' => ['https://client.example.org/cb%23section']];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testNativeClientRejectsRemoteHttpRedirectUri(): void
    {
        $this->assertRejected(
            [
                'redirect_uris' => ['https://client.example.org/cb'],
                'application_type' => 'native',
            ],
            'invalid_redirect_uri',
            'native client',
        );
    }

    public function testNativeClientAllowsCustomSchemeAndLoopbackRedirectUris(): void
    {
        $metadata = [
            'redirect_uris' => [
                'com.example.app:/oauth2redirect',
                'http://localhost:1234/cb',
                'http://127.0.0.1/cb',
                'http://[::1]/cb',
            ],
            'application_type' => 'native',
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testWebImplicitClientRejectsNonHttpsRedirectUri(): void
    {
        $this->assertRejected(
            [
                'redirect_uris' => ['http://client.example.org/cb'],
                'response_types' => ['id_token'],
            ],
            'invalid_redirect_uri',
            'web client using the implicit grant',
        );
    }

    public function testWebImplicitClientRejectsLocalhostRedirectUri(): void
    {
        $this->assertRejected(
            [
                'redirect_uris' => ['https://localhost/cb'],
                'response_types' => ['id_token'],
            ],
            'invalid_redirect_uri',
            'web client using the implicit grant',
        );
    }

    public function testWebCodeClientIsNotConstrainedByImplicitRule(): void
    {
        // Default (web) client not using implicit: an http://localhost redirect stays allowed.
        $metadata = [
            'redirect_uris' => ['http://localhost/cb'],
            'response_types' => ['code'],
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testNonHttpsInitiateLoginUriIsRejected(): void
    {
        $this->assertRejected(
            [
                'redirect_uris' => ['https://client.example.org/cb'],
                'initiate_login_uri' => 'http://client.example.org/x',
            ],
            'invalid_client_metadata',
            'initiate_login_uri',
        );
    }

    public function testImpersonationProtectionRejectsMismatchedHost(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'logo_uri' => 'https://evil.example.com/logo.png'],
            'invalid_client_metadata',
            'impersonation protection',
        );
    }

    public function testImpersonationProtectionAllowsClientUriOnDifferentHost(): void
    {
        // client_uri is intentionally excluded from the host check.
        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'client_uri' => 'https://marketing.example.net/',
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testImpersonationProtectionCanBeDisabled(): void
    {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getDcrImpersonationProtectionEnabled')->willReturn(false);
        $moduleConfigMock->method('getSupportedResponseTypes')
            ->willReturn(['code', 'id_token', 'id_token token']);
        $moduleConfigMock->method('getSupportedGrantTypes')
            ->willReturn(['authorization_code', 'implicit', 'refresh_token']);
        $moduleConfigMock->method('getSupportedTokenEndpointAuthMethods')
            ->willReturn(['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none']);

        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'logo_uri' => 'https://evil.example.com/logo.png',
        ];

        $this->assertSame(
            $metadata,
            (new ClientMetadataValidator($moduleConfigMock, $this->destinationPolicyMock))->validate($metadata),
        );
    }

    public static function refusedDestinationProvider(): array
    {
        return [
            'jwks_uri' => ['jwks_uri', 'https://client.example.org/jwks.json'],
            'signed_jwks_uri' => ['signed_jwks_uri', 'https://client.example.org/signed-jwks'],
            'backchannel_logout_uri' => ['backchannel_logout_uri', 'https://client.example.org/bclo'],
        ];
    }

    #[DataProvider('refusedDestinationProvider')]
    public function testRefusesAUriNamingADestinationThePolicyForbids(string $claim, string $uri): void
    {
        $this->destinationPolicyMock = $this->createMock(DestinationPolicy::class);
        $this->destinationPolicyMock->method('isUriAllowed')
            ->willReturnCallback(fn(string $candidate): bool => $candidate !== $uri);

        $this->assertRejected(
            [
                'redirect_uris' => ['https://client.example.org/cb'],
                $claim => $uri,
            ],
            'invalid_client_metadata',
            $claim,
            isCallerAuthenticated: true,
        );
    }

    /**
     * request_uris is a list, so a single bad entry among good ones has to be caught rather than only the
     * first value being looked at.
     *
     * The refused entry is on its own host deliberately. The policy decides by origin - scheme, host and
     * port - and never by path, so two paths on one host always share a verdict; a case where they differ
     * would be testing a policy that does not exist.
     */
    public function testRefusesARequestUriNamingADestinationThePolicyForbids(): void
    {
        $refused = 'https://elsewhere.example.org/request-object-two';

        $this->destinationPolicyMock = $this->createMock(DestinationPolicy::class);
        $this->destinationPolicyMock->method('isUriAllowed')
            ->willReturnCallback(fn(string $candidate): bool => $candidate !== $refused);

        $this->assertRejected(
            [
                'redirect_uris' => ['https://client.example.org/cb'],
                'request_uris' => ['https://client.example.org/request-object-one', $refused],
            ],
            'invalid_client_metadata',
            $refused,
            isCallerAuthenticated: true,
        );
    }

    /**
     * The destination checks resolve names, and a resolver is bounded by nothing here, so they are not
     * work an unauthenticated caller may order. An open registration is still protected: the refusal
     * happens when the destination is fetched, which is where it always mattered.
     */
    public function testDoesNotResolveDestinationsForAnUnauthenticatedCaller(): void
    {
        $this->destinationPolicyMock = $this->createMock(DestinationPolicy::class);
        $this->destinationPolicyMock->expects($this->never())->method('isUriAllowed');

        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'jwks_uri' => 'https://client.example.org/jwks.json',
            'request_uris' => ['https://client.example.org/request-object'],
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    /**
     * Each distinct destination costs a synchronous DNS lookup, so an unbounded request_uris list is work
     * an unauthenticated caller can order for itself when registration is open. The list has to be refused
     * on length before any of it is resolved.
     */
    public function testRefusesAnOverlongRequestUrisListWithoutResolvingIt(): void
    {
        $this->destinationPolicyMock = $this->createMock(DestinationPolicy::class);
        $this->destinationPolicyMock->expects($this->never())->method('isUriAllowed');

        $requestUris = [];
        for ($i = 0; $i <= 20; $i++) {
            $requestUris[] = sprintf('https://client.example.org/request-object-%d', $i);
        }

        $this->assertRejected(
            [
                'redirect_uris' => ['https://client.example.org/cb'],
                'request_uris' => $requestUris,
            ],
            'invalid_client_metadata',
            'request_uris',
        );
    }

    /**
     * A list repeating one destination is one destination, and must not be charged as many.
     */
    public function testChecksEachDistinctDestinationOnlyOnce(): void
    {
        // What costs a lookup is the host, so many paths on one host are one destination. Twenty Request
        // Object locations on the client's own server is an ordinary registration, and must not become
        // twenty resolver waits.
        $this->destinationPolicyMock = $this->createMock(DestinationPolicy::class);
        $this->destinationPolicyMock->expects($this->once())
            ->method('isUriAllowed')
            ->willReturn(true);

        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'request_uris' => [
                'https://client.example.org/request-object',
                'https://client.example.org/request-object-two',
                'https://client.example.org/other/path#hash',
            ],
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata, isCallerAuthenticated: true));
    }

    /**
     * The policy refuses a URI carrying credentials on the URI itself, not on where it points, so such a
     * URI must never be deduplicated against a clean one sharing its host - it would otherwise be accepted
     * and only fail when something tried to fetch it.
     */
    public function testChecksACredentialBearingUriEvenBehindACleanOneOnTheSameHost(): void
    {
        $withCredentials = 'https://user:secret@client.example.org/jwks.json';

        $this->destinationPolicyMock = $this->createMock(DestinationPolicy::class);
        $this->destinationPolicyMock->method('isUriAllowed')
            ->willReturnCallback(fn(string $candidate): bool => $candidate !== $withCredentials);

        $this->assertRejected(
            [
                'redirect_uris' => ['https://client.example.org/cb'],
                // Checked first, and clean, so it is what the credential-bearing one would hide behind.
                'request_uris' => ['https://client.example.org/request-object'],
                'jwks_uri' => $withCredentials,
            ],
            'invalid_client_metadata',
            'jwks_uri',
            isCallerAuthenticated: true,
        );
    }

    /**
     * The origin is what identifies a destination, so a different scheme or port is a different one even
     * on the same host. Folding those together would let an http URI ride in on an https one.
     */
    public function testTreatsADifferentSchemeOrPortAsADifferentDestination(): void
    {
        $this->destinationPolicyMock = $this->createMock(DestinationPolicy::class);
        $this->destinationPolicyMock->expects($this->exactly(3))
            ->method('isUriAllowed')
            ->willReturn(true);

        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'jwks_uri' => 'https://client.example.org/jwks.json',
            'signed_jwks_uri' => 'https://client.example.org:8443/jwks.json',
            'backchannel_logout_uri' => 'https://other.example.org/bclo',
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata, isCallerAuthenticated: true));
    }

    /**
     * The policy decides destinations, not the shape of the metadata, so a claim the OP never fetches from
     * must not be run past it. logo_uri is shown to a human; refusing it here would be a different rule.
     */
    public function testDoesNotApplyTheDestinationPolicyToUrisItNeverFetches(): void
    {
        $this->destinationPolicyMock = $this->createMock(DestinationPolicy::class);
        $this->destinationPolicyMock->expects($this->never())->method('isUriAllowed');

        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'logo_uri' => 'https://client.example.org/logo.png',
            'client_uri' => 'https://client.example.org/',
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }
}
