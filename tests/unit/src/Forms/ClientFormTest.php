<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Forms;

use ArrayIterator;
use DateTimeImmutable;
use Nette\Forms\Form;
use Nette\InvalidArgumentException;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Auth;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Auth\Source;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Forms\ClientForm;
use SimpleSAML\Module\oidc\Forms\Controls\CsrfProtection;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;

/**
 * One statement in ClientForm is deliberately left uncovered: the `[automatic]` fallback in `getValues()` for a
 * `client_registration_types` value which is not an array. That value comes from the form's own multi-select,
 * which yields an array even when nothing is selected and refuses an out-of-range value outright, so nothing
 * this class can submit reaches the fallback. Its counterpart in `setDefaults()`, which reads the stored client
 * row rather than the control, is reachable and is covered by
 * self::testAClientWithNoStoredRegistrationTypesFallsBackToAutomatic().
 */
#[CoversClass(ClientForm::class)]
#[UsesClass(Helpers::class)]
#[AllowMockObjectsWithoutExpectations]
class ClientFormTest extends TestCase
{
    protected MockObject $csrfProtectionMock;

    protected MockObject $moduleConfigMock;

    protected MockObject $serverRequestMock;

    protected MockObject $sspBridgeMock;

    protected MockObject $sspBridgeAuthMock;

    protected MockObject $sspBridgeAuthSourceMock;

    protected Helpers $helpers;

    protected array $clientDataSample;


    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        parent::setUp();
        $this->csrfProtectionMock =  $this->createMock(CsrfProtection::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getSupportedResponseModes')->willReturn(['query', 'fragment', 'form_post']);
        $this->moduleConfigMock->method('getAcrValuesSupported')
            ->willReturn(['urn:mace:incommon:iap:silver', 'urn:mace:incommon:iap:bronze']);
        $this->moduleConfigMock->method('getSupportedResponseTypes')
            ->willReturn(['code', 'id_token', 'id_token token']);
        $this->moduleConfigMock->method('getSupportedGrantTypes')
            ->willReturn(['authorization_code', 'implicit', 'refresh_token']);
        $this->moduleConfigMock->method('getSupportedTokenEndpointAuthMethods')
            ->willReturn(['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none']);

        $signatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);
        $signatureKeyPairBagMock->method('getAllAlgorithmNamesUnique')->willReturn(['RS256', 'ES256']);
        $this->moduleConfigMock->method('getProtocolSignatureKeyPairBag')->willReturn($signatureKeyPairBagMock);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->helpers = new Helpers();

        $this->sspBridgeAuthMock = $this->createMock(Auth::class);
        $this->sspBridgeMock->method('auth')->willReturn($this->sspBridgeAuthMock);

        $this->sspBridgeAuthSourceMock = $this->createMock(Source::class);
        $this->sspBridgeAuthMock->method('source')->willReturn($this->sspBridgeAuthSourceMock);

        $this->clientDataSample = [
            'id' => 'clientId',
            'secret' => 'clientSecret',
            'name' => 'Test',
            'description' => 'Test',
            'auth_source' => 'default-sp',
            'redirect_uri' => [0 => 'https://example.com/redirect',],
            'scopes' => [0 => 'openid', 1 => 'offline_access', 2 => 'profile',],
            'is_enabled' => false,
            'is_confidential' => true,
            'owner' => null,
            'post_logout_redirect_uri' => [0 => 'https://example.com/',],
            'backchannel_logout_uri' => 'https://example.com/logout',
            'entity_identifier' => 'https://example.com/',
            'client_registration_types' => [0 => 'automatic',],
            'federation_jwks' => ['keys' => [0 => [],],],
            'jwks' => ['keys' => [0 => [],],],
            'jwks_uri' => 'https://example.com/jwks',
            'signed_jwks_uri' => 'https://example.com/signed-jwks',
            'registration_type' => RegistrationTypeEnum::Manual,
            'updated_at' => DateTimeImmutable::__set_state(
                ['date' => '2025-02-05 15:05:27.000000', 'timezone_type' => 3, 'timezone' => 'UTC',],
            ),
            'created_at' => DateTimeImmutable::__set_state(
                ['date' => '2024-12-01 11:54:12.000000', 'timezone_type' => 3, 'timezone' => 'UTC',],
            ),
            'expires_at' => null,
            'allowed_origin' => [],
            ClientEntity::KEY_ALLOWED_RESPONSE_MODES => ['query', 'fragment', 'form_post',],
        ];
    }


    protected function sut(
        ?ModuleConfig $moduleConfig = null,
        ?CsrfProtection $csrfProtection = null,
        ?SspBridge $sspBridge = null,
        ?Helpers $helpers = null,
    ): ClientForm {
        $moduleConfig ??= $this->moduleConfigMock;
        $csrfProtection ??= $this->csrfProtectionMock;
        $sspBridge ??= $this->sspBridgeMock;
        $helpers ??= $this->helpers;

        return new ClientForm(
            $moduleConfig,
            $csrfProtection,
            $sspBridge,
            $helpers,
        );
    }


    public static function validateOriginProvider(): array
    {
        return [
            ['example.com', false],
            ['https://example.com.', true],
            ['http://example.com.', true],
            ['http://foo.', true],
            ['http://foo', true],
            ['https://user:pass@example.com', false],
            ['http://example.com', true],
            ['https://example.com:2020', true],
            ['https://localhost:2020', true],
            ['http://localhost:2020', true],
            ['http://localhost', true],
            ['https://example.com/path', false],
            ['https://example.com:8080/path', false],
            ['http://*.example.com', false],
            ['http://*.example.com.', false],
            ['https://foo.example.com:80', true],
            ['http://*.example', false],
            ['http://foo.*.test.com', false],
            ['http://*', false],
            ['http://*.com', false],
            ['https://test........', false],
            ['https://developer.mozilla.org:80', true],
            ['http://attacker.bar/test.php', false],
            ['https://cors-test.codehappy.dev', true],
            ['http://80.345.28.123', true],
            ['https://127.0.0.1:8080', true],
            ['https://127.0.0.1:8080/path', false],
            ['https://user:pass@127.0.0.1:8080/path', false],
        ];
    }

    /**
     * @param   string  $url
     * @param   bool    $isValid
     *
     * @return void
     * @throws \Exception
     */
    #[DataProvider('validateOriginProvider')]
    #[TestDox('Allowed Origin URL: $url is expected to be $isValid')]
    public function testValidateOrigin(string $url, bool $isValid): void
    {
        $clientForm = $this->sut();
        $clientForm->setValues(['allowed_origin' => $url]);
        $clientForm->validateAllowedOrigin($clientForm);

        $this->assertEquals(!$isValid, $clientForm->hasErrors(), $url);
    }


    public function testSetDefaultsLeavesValidAuthSourceValue(): void
    {
        $this->sspBridgeAuthSourceMock->method('getSources')->willReturn(['default-sp']);

        $sut = $this->sut()->setDefaults($this->clientDataSample);

        $this->assertSame('default-sp', $sut->getValues()['auth_source']);
    }


    public function testSetDefaultsUnsetsAuthSourceIfNotValid(): void
    {
        $sut = $this->sut()->setDefaults($this->clientDataSample);

        $this->assertNull($sut->getValues()['auth_source']);
    }


    public static function redirectUriProvider(): array
    {
        return [
            ['https', false],
            ['https:', false],
            ['example', false],
            ['example.com', false],
            ['example.com/?foo=bar', false],
            ['www.example.com/?foo=bar', false],
            ['https://example', true],
            ['https://example.com', true],
            ['https://example.com/', true],
            ['https://example.com/foo', true],
            ['https://example.com/foo?bar=1', true],

            // To support OID4VCI
            ['openid-credential-offer://', true],
            ['foo://', true],
            ['https://', true],

            // Private-use URI schemes for native apps (RFC8252), with empty authority component
            ['app.immich:///oauth-callback', true],
            ['com.example.app:/oauth2redirect/example-provider', true],
            ['com.example.app:oauth2redirect', true],
            ['urn:ietf:wg:oauth:2.0:oob', true],
            ['x://a', true],

            // Scheme must comply with RFC3986, and no whitespace is allowed
            ['1foo://example.com', false],
            ['foo bar://example.com', false],
            ['  https://example.com', false],
            ['https://example.com/foo bar', false],
            ['://example.com', false],

            // Fragment component is not allowed (OIDC Core, 3.1.2.1)
            ['https://example.com/foo#bar', false],
            ['com.example.app:#oauth2redirect', false],
            ['app.immich:///oauth-callback#foo', false],
        ];
    }


    #[DataProvider('redirectUriProvider')]
    public function testCanValidateRedirectUri(string $url, bool $isValid): void
    {
        $sut = $this->sut();
        $sut->setValues(['redirect_uri' => $url]);
        $sut->validateRedirectUri($sut);

        $this->assertEquals(!$isValid, $sut->hasErrors(), $url);
    }


    public function testIdTokenSignedResponseAlgSelectIsLimitedToSupportedAlgs(): void
    {
        $sut = $this->sut();

        // A supported algorithm is accepted by the select.
        $sut->setValues([ClaimsEnum::IdTokenSignedResponseAlg->value => 'ES256']);
        $this->assertSame('ES256', $sut->getValues()[ClaimsEnum::IdTokenSignedResponseAlg->value]);

        // An unsupported algorithm is rejected by the select (out of allowed set).
        $this->expectException(InvalidArgumentException::class);
        $this->sut()->setValues([ClaimsEnum::IdTokenSignedResponseAlg->value => 'HS256']);
    }


    public function testGrantTypesResponseTypesAndAuthMethodRoundTrip(): void
    {
        $sut = $this->sut();
        $sut->setValues([
            ClaimsEnum::GrantTypes->value => ['authorization_code', 'refresh_token'],
            ClaimsEnum::ResponseTypes->value => ['code'],
            ClaimsEnum::TokenEndpointAuthMethod->value => 'private_key_jwt',
        ]);

        $values = $sut->getValues();
        $this->assertSame(['authorization_code', 'refresh_token'], $values[ClaimsEnum::GrantTypes->value]);
        $this->assertSame(['code'], $values[ClaimsEnum::ResponseTypes->value]);
        $this->assertSame('private_key_jwt', $values[ClaimsEnum::TokenEndpointAuthMethod->value]);
    }


    public function testEmptyTokenEndpointAuthMethodNormalizesToNull(): void
    {
        $values = $this->sut()->getValues();

        $this->assertNull($values[ClaimsEnum::TokenEndpointAuthMethod->value]);
        $this->assertSame([], $values[ClaimsEnum::GrantTypes->value]);
        $this->assertSame([], $values[ClaimsEnum::ResponseTypes->value]);
    }


    public function testDefaultAcrValuesAreConstrainedToSupported(): void
    {
        // The field is a multi-select bound to the OP's supported ACRs. setDefaults (the edit path) drops values
        // that are no longer supported, so the control never receives an out-of-range value.
        $data = array_merge($this->clientDataSample, [
            ClaimsEnum::DefaultAcrValues->value => [
                'urn:mace:incommon:iap:silver',
                'urn:not:supported',
            ],
        ]);
        $sut = $this->sut()->setDefaults($data);

        $values = $sut->getValues();

        $this->assertSame(['urn:mace:incommon:iap:silver'], $values[ClaimsEnum::DefaultAcrValues->value]);
        $this->assertTrue($sut->hasConfiguredAcrValues());
    }


    public function testGrantTypesAreNormalizedToResponseTypeCorrespondence(): void
    {
        // Selecting an implicit response type must pull in the implicit grant type on save, even if the admin
        // only had authorization_code selected.
        $data = array_merge($this->clientDataSample, [
            ClaimsEnum::ResponseTypes->value => ['code', 'id_token'],
            ClaimsEnum::GrantTypes->value => ['authorization_code'],
        ]);
        $sut = $this->sut()->setDefaults($data);

        $values = $sut->getValues();

        $this->assertSame(['authorization_code', 'implicit'], $values[ClaimsEnum::GrantTypes->value]);
        $this->assertSame(['code', 'id_token'], $values[ClaimsEnum::ResponseTypes->value]);
    }


    public function testClientTypeFollowsTokenEndpointAuthMethod(): void
    {
        // `none` => public, regardless of the submitted radio value.
        $values = $this->sut()->setDefaults(array_merge($this->clientDataSample, [
            ClaimsEnum::TokenEndpointAuthMethod->value => 'none',
            'is_confidential' => true,
        ]))->getValues();
        $this->assertFalse($values['is_confidential']);

        // A real authentication method => confidential, regardless of the submitted radio value.
        $values = $this->sut()->setDefaults(array_merge($this->clientDataSample, [
            ClaimsEnum::TokenEndpointAuthMethod->value => 'private_key_jwt',
            'is_confidential' => false,
        ]))->getValues();
        $this->assertTrue($values['is_confidential']);
    }


    public function testNativeApplicationTypeMakesClientPublicWhenNoAuthMethod(): void
    {
        // native + no auth method => public, overriding the submitted radio (mirrors DCR).
        $values = $this->sut()->setDefaults(array_merge($this->clientDataSample, [
            ClaimsEnum::ApplicationType->value => 'native',
            ClaimsEnum::TokenEndpointAuthMethod->value => '',
            'is_confidential' => true,
        ]))->getValues();
        $this->assertFalse($values['is_confidential']);

        // An explicit auth method still takes precedence over the native hint.
        $values = $this->sut()->setDefaults(array_merge($this->clientDataSample, [
            ClaimsEnum::ApplicationType->value => 'native',
            ClaimsEnum::TokenEndpointAuthMethod->value => 'client_secret_basic',
            'is_confidential' => false,
        ]))->getValues();
        $this->assertTrue($values['is_confidential']);
    }


    public function testClientTypeStandsWhenAuthMethodUnset(): void
    {
        // When no auth method is selected, the explicit confidential/public choice is preserved.
        $values = $this->sut()->setDefaults(array_merge($this->clientDataSample, [
            ClaimsEnum::TokenEndpointAuthMethod->value => '',
            'is_confidential' => true,
        ]))->getValues();
        $this->assertTrue($values['is_confidential']);
    }


    public function testInformationalMetadataRoundTrip(): void
    {
        $sut = $this->sut();
        $sut->setValues([
            ClaimsEnum::LogoUri->value => 'https://client.example.org/logo.png',
            ClaimsEnum::ClientUri->value => 'https://client.example.org/',
            ClaimsEnum::PolicyUri->value => 'https://client.example.org/policy',
            ClaimsEnum::TosUri->value => 'https://client.example.org/tos',
            ClaimsEnum::ApplicationType->value => 'web',
            ClaimsEnum::Contacts->value => "admin@example.org\nops@example.org",
        ]);

        $values = $sut->getValues();
        $this->assertSame('https://client.example.org/logo.png', $values[ClaimsEnum::LogoUri->value]);
        $this->assertSame('https://client.example.org/', $values[ClaimsEnum::ClientUri->value]);
        $this->assertSame('https://client.example.org/policy', $values[ClaimsEnum::PolicyUri->value]);
        $this->assertSame('https://client.example.org/tos', $values[ClaimsEnum::TosUri->value]);
        $this->assertSame('web', $values[ClaimsEnum::ApplicationType->value]);
        $this->assertSame(['admin@example.org', 'ops@example.org'], $values[ClaimsEnum::Contacts->value]);
    }


    public function testEmptyInformationalMetadataNormalizesToNullOrEmpty(): void
    {
        $values = $this->sut()->getValues();

        $this->assertNull($values[ClaimsEnum::LogoUri->value]);
        $this->assertNull($values[ClaimsEnum::ApplicationType->value]);
        $this->assertSame([], $values[ClaimsEnum::Contacts->value]);
    }


    public function testAcceptsValidAuthProcFilters(): void
    {
        $clientForm = $this->sut();
        $clientForm->setValues([
            ClientEntity::KEY_AUTH_PROC_FILTERS =>
                '{"60": {"class": "core:AttributeAdd", "groups": ["members"]}}',
        ]);
        $clientForm->validateAuthProcFilters($clientForm);

        $this->assertFalse($clientForm->hasErrors());
        $this->assertSame(
            ['60' => ['class' => 'core:AttributeAdd', 'groups' => ['members']]],
            $clientForm->getValues()[ClientEntity::KEY_AUTH_PROC_FILTERS],
        );
    }


    public function testCastsNumericAuthProcFilterPrioritiesToInt(): void
    {
        $clientForm = $this->sut();
        // "08" is NOT auto-cast to int by PHP (leading zero), so this verifies
        // the explicit normalization actually does something.
        $clientForm->setValues([
            ClientEntity::KEY_AUTH_PROC_FILTERS => '{"08": {"class": "core:AttributeAdd"}}',
        ]);

        $filters = $clientForm->getValues()[ClientEntity::KEY_AUTH_PROC_FILTERS];

        $this->assertSame([8 => ['class' => 'core:AttributeAdd']], $filters);
        $this->assertIsInt(array_key_first($filters));
    }


    public function testRejectsAuthProcFiltersWithInvalidJson(): void
    {
        $clientForm = $this->sut();
        $clientForm->setValues([ClientEntity::KEY_AUTH_PROC_FILTERS => '{not-valid-json']);
        // getValues() (invoked by the validator) records the JSON decoding error.
        $clientForm->validateAuthProcFilters($clientForm);

        $this->assertTrue($clientForm->hasErrors());
    }


    public function testRejectsAuthProcFilterWithoutClass(): void
    {
        $clientForm = $this->sut();
        $clientForm->setValues([ClientEntity::KEY_AUTH_PROC_FILTERS => '{"60": {"groups": ["members"]}}']);
        $clientForm->validateAuthProcFilters($clientForm);

        $this->assertTrue($clientForm->hasErrors());
    }


    public function testSetDefaultsAndGetValuesRoundTripAuthProcFilters(): void
    {
        $this->sspBridgeAuthSourceMock->method('getSources')->willReturn(['default-sp']);

        $filters = [60 => ['class' => 'core:AttributeAdd', 'groups' => ['members']]];
        $data = $this->clientDataSample;
        $data[ClientEntity::KEY_AUTH_PROC_FILTERS] = $filters;

        $sut = $this->sut()->setDefaults($data);

        // setDefaults() encodes the array to a JSON string for the textarea, and
        // getValues() decodes it back to the original structure.
        $this->assertSame(
            ['60' => ['class' => 'core:AttributeAdd', 'groups' => ['members']]],
            $sut->getValues()[ClientEntity::KEY_AUTH_PROC_FILTERS],
        );
    }


    public function testAddClaimsToIdTokenDefaultsToFalse(): void
    {
        $this->assertFalse($this->sut()->getValues()[ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN]);
    }


    public function testSetDefaultsAndGetValuesRoundTripAddClaimsToIdToken(): void
    {
        $this->sspBridgeAuthSourceMock->method('getSources')->willReturn(['default-sp']);

        $data = $this->clientDataSample;
        $data[ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN] = true;

        $sut = $this->sut()->setDefaults($data);

        $this->assertTrue($sut->getValues()[ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN]);
    }


    /**
     * The form-level errors the validators record, re-indexed. Nette returns them with their original keys,
     * which are not contiguous once it drops a duplicate.
     *
     * @return string[]
     */
    protected function ownErrors(ClientForm $form): array
    {
        return array_values($form->getOwnErrors());
    }


    /**
     * A form which is not the SUT, whose multi-select offers a value this OP does not support.
     *
     * The validators accept any `Nette\Forms\Form`, and that is what their type and range guards exist for.
     * Those guards cannot fire for a value taken from the SUT, which defends the same values twice over
     * before they get there: the multi-select refuses an out-of-range selection outright
     * (Nette\InvalidArgumentException), and ClientForm::getValues() then intersects the selection with the
     * supported set. The guards are a third layer behind those two, so a foreign form is the only way to
     * show they work at all.
     */
    protected function foreignFormWithSelection(string $name, array $items, array $selected): Form
    {
        $form = new Form();
        $form->addMultiSelect($name, null, $items, 3);
        $form->setDefaults([$name => $selected]);

        return $form;
    }


    /**
     * A form which is not the SUT, holding a plain string where the SUT's own control yields an array.
     *
     * @see self::foreignFormWithSelection() for why a foreign form is needed at all.
     */
    protected function foreignFormWithText(string $name, string $value): Form
    {
        $form = new Form();
        $form->addText($name);
        $form->setDefaults([$name => $value]);

        return $form;
    }


    public static function postLogoutRedirectUriProvider(): array
    {
        return [
            'https URL' => ['https://example.com/logged-out', true],
            'http URL' => ['http://example.com/logged-out', true],
            'private-use scheme, RFC8252 native app' => ['app.example:///logged-out', true],
            'custom scheme with empty authority' => ['openid-credential-offer://', true],
            'no scheme' => ['example.com/logged-out', false],
            'scheme alone' => ['https:', false],
            'fragment component' => ['https://example.com/logged-out#done', false],
            'leading whitespace' => ['  https://example.com/logged-out', false],
        ];
    }


    /**
     * @throws \Exception
     */
    #[DataProvider('postLogoutRedirectUriProvider')]
    #[TestDox('Post-logout redirect URI: $uri is expected to be $isValid')]
    public function testCanValidatePostLogoutRedirectUri(string $uri, bool $isValid): void
    {
        $sut = $this->sut();
        $sut->setValues(['post_logout_redirect_uri' => $uri]);
        $sut->validatePostLogoutRedirectUri($sut);

        $this->assertSame($isValid, $this->ownErrors($sut) === [], $uri);

        if (!$isValid) {
            // The message prefix is what tells this validator's complaint from its neighbours'.
            $this->assertSame('Invalid post-logout redirect URI: ' . $uri, $this->ownErrors($sut)[0]);
        }
    }


    /**
     * @throws \Exception
     */
    public function testEveryLineOfThePostLogoutRedirectUriFieldIsValidated(): void
    {
        // The field is a textarea holding one URI per line, so a bad line must be reported even when the
        // first line is fine.
        $sut = $this->sut();
        $sut->setValues(['post_logout_redirect_uri' => "https://example.com/one\nnot-a-uri\nhttps://example.com/two"]);
        $sut->validatePostLogoutRedirectUri($sut);

        $this->assertSame(['Invalid post-logout redirect URI: not-a-uri'], $this->ownErrors($sut));
    }


    public static function backChannelLogoutUriProvider(): array
    {
        return [
            'https URL' => ['https://example.com/backchannel-logout', true],
            'http URL' => ['http://example.com/backchannel-logout', true],
            'with query component' => ['https://example.com/logout?tenant=1', true],
            'with port' => ['https://example.com:8443/logout', true],
            'uppercase scheme' => ['HTTPS://EXAMPLE.COM/logout', true],
            'non-http scheme' => ['foo://example.com/logout', false],
            'host starting with a dot' => ['https://.example.com/logout', false],
            'fragment component' => ['https://example.com/logout#done', false],
            'no scheme' => ['example.com/logout', false],
        ];
    }


    /**
     * @throws \Exception
     */
    #[DataProvider('backChannelLogoutUriProvider')]
    #[TestDox('Back-channel logout URI: $uri is expected to be $isValid')]
    public function testCanValidateBackChannelLogoutUri(string $uri, bool $isValid): void
    {
        $sut = $this->sut();
        $sut->setValues(['backchannel_logout_uri' => $uri]);
        $sut->validateBackChannelLogoutUri($sut);

        $this->assertSame($isValid, $this->ownErrors($sut) === [], $uri);

        if (!$isValid) {
            $this->assertSame('Invalid back-channel logout URI: ' . $uri, $this->ownErrors($sut)[0]);
        }
    }


    public static function entityIdentifierProvider(): array
    {
        return [
            'https URL' => ['https://example.com/entity', true],
            'http URL' => ['http://example.com/entity', true],
            'bare host' => ['https://example.com', true],
            'with port' => ['https://example.com:8443/entity', true],
            // The one thing that separates this pattern from the back-channel logout one.
            'with query component' => ['https://example.com/entity?tenant=1', false],
            'non-http scheme' => ['foo://example.com/entity', false],
            'host starting with a dot' => ['https://.example.com/entity', false],
            'fragment component' => ['https://example.com/entity#done', false],
            'no scheme' => ['example.com/entity', false],
        ];
    }


    /**
     * @throws \Exception
     */
    #[DataProvider('entityIdentifierProvider')]
    #[TestDox('Entity Identifier: $uri is expected to be $isValid')]
    public function testCanValidateEntityIdentifier(string $uri, bool $isValid): void
    {
        $sut = $this->sut();
        $sut->setValues(['entity_identifier' => $uri]);
        $sut->validateEntityIdentifier($sut);

        $this->assertSame($isValid, $this->ownErrors($sut) === [], $uri);

        if (!$isValid) {
            $this->assertSame('Invalid Entity Identifier URI: ' . $uri, $this->ownErrors($sut)[0]);
        }
    }


    /**
     * @throws \Exception
     */
    public function testEachUriFieldIsValidatedByItsOwnPattern(): void
    {
        // Three URI fields, three different patterns, and a plain `https://example.com` satisfies all of them
        // -- so a validator wired to a neighbouring pattern would pass every single-field test above. These
        // three shapes separate the patterns from each other:
        //   - a non-http scheme is accepted for redirect-style URIs only (REGEX_URI);
        //   - a query component is accepted everywhere except the Entity Identifier (REGEX_HTTP_URI_PATH);
        //   - a path with neither is accepted by all three.
        // Within a case the three fields share the shape but hold distinct values, and the whole message is
        // asserted rather than its prefix: two validators swapped for each other would keep every verdict,
        // but each would then quote the other field's value.
        $cases = [
            // URI shape, accepted as post-logout redirect / back-channel logout / entity identifier.
            ['foo://example.com/%s', true, false, false],
            ['https://example.com/%s?q=1', true, true, false],
            ['https://example.com/%s', true, true, true],
        ];

        foreach ($cases as [$shape, $okAsPostLogout, $okAsBackChannel, $okAsEntityIdentifier]) {
            $postLogoutUri = sprintf($shape, 'post-logout');
            $backChannelUri = sprintf($shape, 'back-channel');
            $entityIdentifier = sprintf($shape, 'entity');

            $sut = $this->sut();
            $sut->setValues([
                'post_logout_redirect_uri' => $postLogoutUri,
                'backchannel_logout_uri' => $backChannelUri,
                'entity_identifier' => $entityIdentifier,
            ]);
            $sut->validatePostLogoutRedirectUri($sut);
            $sut->validateBackChannelLogoutUri($sut);
            $sut->validateEntityIdentifier($sut);

            $errors = $this->ownErrors($sut);

            $this->assertSame(
                $okAsPostLogout,
                !in_array('Invalid post-logout redirect URI: ' . $postLogoutUri, $errors, true),
                $postLogoutUri,
            );
            $this->assertSame(
                $okAsBackChannel,
                !in_array('Invalid back-channel logout URI: ' . $backChannelUri, $errors, true),
                $backChannelUri,
            );
            $this->assertSame(
                $okAsEntityIdentifier,
                !in_array('Invalid Entity Identifier URI: ' . $entityIdentifier, $errors, true),
                $entityIdentifier,
            );
            // Nothing else was reported, so a validator reading a neighbour's field cannot hide behind an
            // extra message that happens to carry the right prefix.
            $expectedRejections = count(array_filter(
                [$okAsPostLogout, $okAsBackChannel, $okAsEntityIdentifier],
                fn(bool $accepted): bool => !$accepted,
            ));
            $this->assertCount($expectedRejections, $errors, $shape);
        }
    }


    /**
     * @throws \Exception
     */
    public function testUnsetOptionalUriFieldsAreNotValidated(): void
    {
        // Every optional URI field is empty on a fresh form, and every validator which reads one runs here.
        // getValues() normalizes the single-value fields to null and the textareas to empty lists, and each
        // validator then skips the empty value rather than running it through a pattern which would reject
        // it -- by testing for null, by iterating an empty list, or, for the two JWKS URIs, by filtering
        // them out before matching.
        $sut = $this->sut();
        $sut->validatePostLogoutRedirectUri($sut);
        $sut->validateBackChannelLogoutUri($sut);
        $sut->validateEntityIdentifier($sut);
        $sut->validateJwksUri($sut);
        $sut->validateAllowedOrigin($sut);
        $sut->validateRequestUris($sut);

        $this->assertSame([], $this->ownErrors($sut));
    }


    /**
     * @throws \Exception
     */
    public function testCanValidateClientRegistrationTypes(): void
    {
        $sut = $this->sut();
        $sut->setValues(['client_registration_types' => ['automatic', 'explicit']]);
        $sut->validateClientRegistrationTypes($sut);

        $this->assertSame([], $this->ownErrors($sut));
    }


    /**
     * @throws \Exception
     */
    public function testAnUnknownClientRegistrationTypeIsReported(): void
    {
        $sut = $this->sut();
        $sut->validateClientRegistrationTypes($this->foreignFormWithSelection(
            'client_registration_types',
            ['automatic' => 'automatic', 'invented' => 'invented'],
            ['invented'],
        ));

        $this->assertSame(['Invalid value: invented'], $this->ownErrors($sut));
    }


    /**
     * Only the named validator runs here, deliberately. Both validators hand their field to the same checker,
     * which reports the same message either way, so only the value quoted in the message says which field was
     * read -- and running both validators over one malformed field and one sound one would let a pair of
     * validators wired to each other's field produce exactly the expected single error.
     *
     * @throws \Exception
     */
    public function testTheFederationJwksValidatorReadsTheFederationField(): void
    {
        $sut = $this->sut();
        $sut->setValues([
            'federation_jwks' => '{"no_keys_here": "federation-side"}',
            'jwks' => '{"keys": [{"kid": "protocol-side"}]}',
        ]);
        $sut->validateFederationJwks($sut);

        $errors = $this->ownErrors($sut);
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('No keys property in JWKS', $errors[0]);
        $this->assertStringContainsString('federation-side', $errors[0]);
    }


    /**
     * @see self::testTheFederationJwksValidatorReadsTheFederationField() for why only one validator runs.
     *
     * @throws \Exception
     */
    public function testTheProtocolJwksValidatorReadsTheProtocolField(): void
    {
        $sut = $this->sut();
        $sut->setValues([
            'federation_jwks' => '{"keys": [{"kid": "federation-side"}]}',
            'jwks' => '{"no_keys_here": "protocol-side"}',
        ]);
        $sut->validateProtocolJwks($sut);

        $errors = $this->ownErrors($sut);
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('No keys property in JWKS', $errors[0]);
        $this->assertStringContainsString('protocol-side', $errors[0]);
    }


    public static function malformedJwksProvider(): array
    {
        return [
            'a scalar' => [123, 'Invalid JWKS format'],
            'a string' => ['{"keys": []}', 'Invalid JWKS format'],
            'an array with no keys property' => [['kid' => 'sig-1'], 'No keys property in JWKS'],
            'an array whose keys property is empty' => [['keys' => []], 'Empty keys in JWKS'],
        ];
    }


    /**
     * @throws \Exception
     */
    #[DataProvider('malformedJwksProvider')]
    public function testValidateJwksReportsEachMalformedShape(mixed $jwks, string $expectedMessage): void
    {
        $sut = $this->sut();
        $sut->validateJwks($jwks);

        $errors = $this->ownErrors($sut);
        $this->assertCount(1, $errors);
        $this->assertStringContainsString($expectedMessage, $errors[0]);
    }


    /**
     * @throws \Exception
     */
    public function testValidateJwksAcceptsAWellFormedSetAndTreatsNullAsAbsent(): void
    {
        $sut = $this->sut();
        $sut->validateJwks(null);
        $sut->validateJwks(['keys' => [['kid' => 'sig-1']]]);

        $this->assertSame([], $this->ownErrors($sut));
    }


    /**
     * Pinned, not endorsed. validateJwks() checks that `keys` is present and not empty, but never that it is
     * a list, so a JWKS whose `keys` property is a non-empty scalar passes the form and is stored. Queued in
     * the release-readiness handoff; a fix has to update this test deliberately.
     *
     * @throws \Exception
     */
    public function testAJwksWhoseKeysPropertyIsNotAListIsAccepted(): void
    {
        $sut = $this->sut();
        $sut->validateJwks(['keys' => 'not-a-list']);
        $sut->validateJwks(['keys' => 123]);

        $this->assertSame([], $this->ownErrors($sut));
    }


    /**
     * @throws \Exception
     */
    public function testAJwksFieldHoldingAJsonScalarIsReportedAsMalformed(): void
    {
        // getValues() decodes the field before the checker sees it, so valid JSON which is not an object
        // reaches it as a scalar. This is how the "invalid format" branch is reached from the form itself.
        $sut = $this->sut();
        $sut->setValues(['jwks' => '123']);
        $sut->validateProtocolJwks($sut);

        $errors = $this->ownErrors($sut);
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('Invalid JWKS format', $errors[0]);
    }


    /**
     * @throws \Exception
     */
    public function testTheSignedJwksUriIsValidatedAlongsideThePlainOne(): void
    {
        // One validator covers two separate fields; a bad value in either has to be reported.
        $sut = $this->sut();
        $sut->setValues([
            'jwks_uri' => 'https://example.com/jwks',
            'signed_jwks_uri' => 'foo://example.com/signed-jwks',
        ]);
        $sut->validateJwksUri($sut);

        $this->assertSame(['Invalid JWKS URI: foo://example.com/signed-jwks'], $this->ownErrors($sut));
    }


    /**
     * @throws \Exception
     */
    public function testThePlainJwksUriIsValidatedAlongsideTheSignedOne(): void
    {
        $sut = $this->sut();
        $sut->setValues([
            'jwks_uri' => 'not-a-uri',
            'signed_jwks_uri' => 'https://example.com/signed-jwks',
        ]);
        $sut->validateJwksUri($sut);

        $this->assertSame(['Invalid JWKS URI: not-a-uri'], $this->ownErrors($sut));
    }


    /**
     * @throws \Exception
     */
    public function testRequestUrisMustBeHttpsUrls(): void
    {
        $sut = $this->sut();
        $sut->setValues([
            ClaimsEnum::RequestUris->value =>
                "https://example.com/one.jwt\nhttp://example.com/insecure.jwt\nHTTPS://example.com/two.jwt",
        ]);
        $sut->validateRequestUris($sut);

        // The scheme comparison is case-insensitive, so only the plain http URI is reported.
        $this->assertSame(
            ['Request URI must be an HTTPS URL: http://example.com/insecure.jwt'],
            $this->ownErrors($sut),
        );
    }


    /**
     * @throws \Exception
     */
    public function testRequestUrisAreReportedWhenTheyAreNotAList(): void
    {
        $sut = $this->sut();
        $sut->validateRequestUris(
            $this->foreignFormWithText(ClaimsEnum::RequestUris->value, 'https://example.com/one.jwt'),
        );

        $this->assertSame(
            ["Unexpected Request URIs format (expected array): 'https://example.com/one.jwt'"],
            $this->ownErrors($sut),
        );
    }


    /**
     * @throws \Exception
     */
    public function testANonStringRequestUriIsReported(): void
    {
        $sut = $this->sut();
        $sut->validateRequestUris($this->foreignFormWithSelection(
            ClaimsEnum::RequestUris->value,
            [1 => 'one', 2 => 'two'],
            [1],
        ));

        $this->assertSame(['Request URI must be a string: 1'], $this->ownErrors($sut));
    }


    /**
     * @throws \Exception
     */
    public function testCanValidateAllowedResponseModes(): void
    {
        $sut = $this->sut();
        $sut->setValues([ClientEntity::KEY_ALLOWED_RESPONSE_MODES => ['query', 'form_post']]);
        $sut->validateResponseModes($sut);

        $this->assertSame([], $this->ownErrors($sut));
    }


    /**
     * @throws \Exception
     */
    public function testAResponseModeTheOpDoesNotSupportIsReported(): void
    {
        $sut = $this->sut();
        $sut->validateResponseModes($this->foreignFormWithSelection(
            ClientEntity::KEY_ALLOWED_RESPONSE_MODES,
            ['query' => 'query', 'web_message' => 'web_message'],
            ['web_message'],
        ));

        $this->assertSame(['Invalid value: web_message'], $this->ownErrors($sut));
    }


    /**
     * Pinned, not endorsed. Of the multi-selects setDefaults() fills, allowed_response_modes is the only one
     * whose stored value is not filtered against what the OP currently supports -- scopes, grant types,
     * response types and default ACR values all are, and an unsupported token endpoint auth method is nulled.
     * A stored value outside the supported set therefore reaches the control, which refuses it, and the edit
     * screen of that client fails with a Nette exception instead of quietly dropping the stale value the way
     * every neighbouring field does.
     *
     * Not reachable from configuration today: ModuleConfig::getSupportedResponseModes() is a hardcoded list
     * of three, and the field is written only by this form. It is reachable for a row written by hand or by
     * other tooling, and it is what would happen to every stored client holding a mode that a later version
     * of the module stopped supporting -- which is exactly the case the neighbouring fields defend against.
     *
     * Queued in the release-readiness handoff; this test asserts the present behaviour so that a fix has to
     * update it deliberately.
     *
     * @throws \Exception
     */
    public function testEditingAClientHoldingAnUnsupportedResponseModeFails(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('web_message');

        $this->sut()->setDefaults(array_merge($this->clientDataSample, [
            ClientEntity::KEY_ALLOWED_RESPONSE_MODES => ['query', 'web_message'],
        ]));
    }


    /**
     * The contrast to the test above, over every neighbouring field its docblock names: each drops or nulls
     * the value the OP no longer offers, and the admin can still open the client.
     *
     * @throws \Exception
     */
    public function testStaleValuesInEveryOtherMultiSelectAreDroppedRatherThanFatal(): void
    {
        $this->moduleConfigMock->method('getScopes')->willReturn([
            'openid' => ['description' => 'openid'],
            'profile' => ['description' => 'profile'],
        ]);
        $this->sspBridgeAuthSourceMock->method('getSources')->willReturn(['default-sp']);

        $values = $this->sut()->setDefaults(array_merge($this->clientDataSample, [
            'scopes' => ['openid', 'profile', 'retired_scope'],
            // Deliberately not `authorization_code`: the `code` response type below requires it, so
            // getValues() would put it back through the response-type correspondence and the assertion
            // would hold even if setDefaults() had dropped the stored grant types altogether.
            ClaimsEnum::GrantTypes->value => ['refresh_token', 'retired_grant_type'],
            ClaimsEnum::ResponseTypes->value => ['code', 'retired_response_type'],
            ClaimsEnum::DefaultAcrValues->value => ['urn:mace:incommon:iap:silver', 'urn:retired'],
            ClaimsEnum::TokenEndpointAuthMethod->value => 'retired_auth_method',
        ]))->getValues();

        $this->assertSame(['openid', 'profile'], array_values($values['scopes']));
        // The stored `refresh_token` survives; `authorization_code` is appended because `code` requires it.
        $this->assertSame(['refresh_token', 'authorization_code'], $values[ClaimsEnum::GrantTypes->value]);
        $this->assertSame(['code'], $values[ClaimsEnum::ResponseTypes->value]);
        $this->assertSame(['urn:mace:incommon:iap:silver'], $values[ClaimsEnum::DefaultAcrValues->value]);
        $this->assertNull($values[ClaimsEnum::TokenEndpointAuthMethod->value]);
    }


    /**
     * @throws \Exception
     */
    public function testAFederationJwksSyntaxErrorIsReportedAndClearsOnlyThatField(): void
    {
        $sut = $this->sut();
        $sut->setValues([
            'federation_jwks' => '{not json',
            'jwks' => '{"keys": [{"kid": "protocol-side"}]}',
        ]);

        $values = $sut->getValues();

        $this->assertNull($values['federation_jwks']);
        $this->assertSame(['keys' => [['kid' => 'protocol-side']]], $values['jwks']);

        $errors = $this->ownErrors($sut);
        $this->assertCount(1, $errors);
        $this->assertStringStartsWith('Federation JSON error: ', $errors[0]);
    }


    /**
     * @throws \Exception
     */
    public function testAProtocolJwksSyntaxErrorIsReportedAndClearsOnlyThatField(): void
    {
        $sut = $this->sut();
        $sut->setValues([
            'federation_jwks' => '{"keys": [{"kid": "federation-side"}]}',
            'jwks' => '{not json',
        ]);

        $values = $sut->getValues();

        $this->assertNull($values['jwks']);
        $this->assertSame(['keys' => [['kid' => 'federation-side']]], $values['federation_jwks']);

        $errors = $this->ownErrors($sut);
        $this->assertCount(1, $errors);
        $this->assertStringStartsWith('JWKS JSON error: ', $errors[0]);
    }


    /**
     * @throws \Exception
     */
    public function testSetDefaultsAcceptsATraversable(): void
    {
        $this->sspBridgeAuthSourceMock->method('getSources')->willReturn(['default-sp']);

        $values = $this->sut()->setDefaults(new ArrayIterator($this->clientDataSample))->getValues();

        // Asserted on the payload rather than on not throwing, so a conversion which silently lost the data
        // would still fail.
        $this->assertSame('default-sp', $values['auth_source']);
        $this->assertSame(['https://example.com/redirect'], array_values($values['redirect_uri']));
    }


    /**
     * @throws \Exception
     */
    public function testSetDefaultsAcceptsAPlainObject(): void
    {
        $this->sspBridgeAuthSourceMock->method('getSources')->willReturn(['default-sp']);

        $values = $this->sut()->setDefaults((object)$this->clientDataSample)->getValues();

        $this->assertSame('default-sp', $values['auth_source']);
        $this->assertSame(['https://example.com/redirect'], array_values($values['redirect_uri']));
    }


    /**
     * @throws \Exception
     */
    public function testAClientWithNoStoredRegistrationTypesFallsBackToAutomatic(): void
    {
        $this->sspBridgeAuthSourceMock->method('getSources')->willReturn(['default-sp']);

        // The fallback is the only possible source of a value here, since the column holds none.
        $withoutTypes = $this->sut()->setDefaults(array_merge($this->clientDataSample, [
            'client_registration_types' => null,
        ]));
        $this->assertSame(
            ['automatic'],
            array_values($withoutTypes->getValues()['client_registration_types']),
        );

        // A stored value stands rather than being replaced by that fallback.
        $withTypes = $this->sut()->setDefaults(array_merge($this->clientDataSample, [
            'client_registration_types' => ['explicit'],
        ]));
        $this->assertSame(
            ['explicit'],
            array_values($withTypes->getValues()['client_registration_types']),
        );

        // An empty list is not an absent one: it is an array, so it passes through the intersection and no
        // fallback applies. ClientEntity::getClientRegistrationTypes() does fall back for an empty list, so
        // the two disagree -- reachable only for a hand-written row, since ClientEntity::getState() writes
        // the getter's output and so normalizes an empty list to `automatic` before it is ever stored.
        $withEmptyTypes = $this->sut()->setDefaults(array_merge($this->clientDataSample, [
            'client_registration_types' => [],
        ]));
        $this->assertSame(
            [],
            array_values($withEmptyTypes->getValues()['client_registration_types']),
        );
    }


    /**
     * @throws \Exception
     */
    public function testSetDefaultsRendersOnlyTheStringRequestUrisAndContacts(): void
    {
        $this->sspBridgeAuthSourceMock->method('getSources')->willReturn(['default-sp']);

        $values = $this->sut()->setDefaults(array_merge($this->clientDataSample, [
            ClaimsEnum::RequestUris->value => ['https://example.com/one.jwt', 42, 'https://example.com/two.jwt'],
            ClaimsEnum::Contacts->value => ['admin@example.org', 42, 'ops@example.org'],
        ]))->getValues();

        // Both fields are textareas holding one entry per line, so a non-string entry is dropped rather than
        // rendered into the field.
        $this->assertSame(
            ['https://example.com/one.jwt', 'https://example.com/two.jwt'],
            array_values($values[ClaimsEnum::RequestUris->value]),
        );
        $this->assertSame(
            ['admin@example.org', 'ops@example.org'],
            array_values($values[ClaimsEnum::Contacts->value]),
        );
    }


    /**
     * @throws \Exception
     * @throws \JsonException
     */
    public function testTheResponseTypeGrantTypeMapIsRestrictedToTheResponseTypesTheOpOffers(): void
    {
        // Read by the admin form's JavaScript to select the grant types a chosen response type requires. The
        // full correspondence table also carries the three hybrid response types, which this OP does not
        // advertise and which therefore must not reach the browser.
        $map = json_decode($this->sut()->getResponseTypeGrantTypeMapJson(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame(
            [
                'code' => ['authorization_code'],
                'id_token' => ['implicit'],
                'id_token token' => ['implicit'],
            ],
            $map,
        );
    }


    /**
     * @throws \Exception
     */
    public function testAuthProcFiltersMustDecodeToAnObject(): void
    {
        $sut = $this->sut();
        // Valid JSON, but a bare string rather than the priority-keyed object the processing chain expects.
        $sut->setValues([ClientEntity::KEY_AUTH_PROC_FILTERS => '"core:AttributeAdd"']);
        $sut->validateAuthProcFilters($sut);

        $this->assertSame(
            ['Authentication Processing Filters must be a JSON object.'],
            $this->ownErrors($sut),
        );
    }


    /**
     * @throws \Exception
     */
    public function testAnAuthProcFilterMayBeAClassStringOrAnObjectButNothingElse(): void
    {
        $sut = $this->sut();
        $sut->setValues([
            ClientEntity::KEY_AUTH_PROC_FILTERS =>
                '{"50": "core:AttributeAdd", "60": {"class": "core:AttributeMap"}, "70": 42}',
        ]);
        $sut->validateAuthProcFilters($sut);

        // The class string at priority 50 and the object at 60 are both accepted; only the number is
        // reported. A filter object missing its `class` property is covered by
        // self::testRejectsAuthProcFilterWithoutClass().
        $errors = $this->ownErrors($sut);
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('must be a class string or an object', $errors[0]);
        $this->assertStringContainsString('42', $errors[0]);
    }
}
