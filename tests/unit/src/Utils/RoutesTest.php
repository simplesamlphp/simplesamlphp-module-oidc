<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Module;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use TypeError;

/**
 * `Routes` is one method of substance and a large set of thin wrappers around it.
 *
 * `getModuleUrl()` prefixes the resource with the module name taken from `ModuleConfig` and hands it to the
 * SimpleSAMLphp module bridge. Each `url*()` method names exactly one `RoutesEnum` case and passes
 * its string value on; four of them also inject a `client_id` parameter, and two substitute an
 * identifier into the case's path template before passing the result.
 *
 * A wrapper that thin has one interesting failure mode: naming the wrong enum case. Both cases are valid
 * strings of the same type, so the result is a working URL to the wrong endpoint, which neither the type
 * system nor the static analysers can tell apart from the right one. The tables below therefore pair each
 * method with the literal path it has to produce. The expectation is written out rather than read back from
 * `RoutesEnum` because these strings are the module's public URL surface: several are fixed by
 * specification, and `urlStatusList()` builds a URL which is minted once and stored on the list, then
 * repeated verbatim by every Status List Token and by the credentials which reference it. The test pins the
 * wire format instead of agreeing with whatever the enum happens to say later.
 *
 * `testEveryUrlMethodIsCoveredByOneOfTheTables()` reflects over the class and fails when a `url*()` method
 * exists which no table names, so a route added later cannot arrive untested in silence.
 *
 * The module bridge is mocked with a callback which records the resource and the parameters it was handed
 * and returns a URL built from them, so one assertion on the returned string covers both halves. `SspBridge`
 * holds its bridges in static properties, but mocking it means the real ones are never constructed, so
 * nothing carries between tests.
 *
 * The module name in the fixture is deliberately not `oidc`, which is what `ModuleConfig::MODULE_NAME`
 * actually holds: `testTakesTheModuleNameFromTheConfiguration()` fails if the prefix is ever hardcoded.
 */
#[CoversClass(Routes::class)]
#[AllowMockObjectsWithoutExpectations]
class RoutesTest extends TestCase
{
    protected const string BASE_URL = 'https://op.example.org/module.php/';

    protected const string CLIENT_ID = 'test-client-id';

    protected const string MODULE_NAME = 'test-module-name';


    protected MockObject $moduleConfigMock;

    protected MockObject $sspBridgeMock;

    protected MockObject $sspBridgeModuleMock;

    /** @var array<int, array{resource: string, parameters: array}> */
    protected array $moduleUrlCalls;


    protected function setUp(): void
    {
        $this->moduleUrlCalls = [];

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('moduleName')->willReturn(self::MODULE_NAME);

        $this->sspBridgeModuleMock = $this->createMock(Module::class);
        $this->sspBridgeModuleMock->method('getModuleUrl')
            ->willReturnCallback(
                function (string $resource, array $parameters = []): string {
                    $this->moduleUrlCalls[] = ['resource' => $resource, 'parameters' => $parameters];

                    return self::BASE_URL . $resource .
                        ($parameters === [] ? '' : '?' . http_build_query($parameters));
                },
            );

        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->sspBridgeMock->method('module')->willReturn($this->sspBridgeModuleMock);
    }


    protected function sut(?ModuleConfig $moduleConfig = null): Routes
    {
        return new Routes(
            $moduleConfig ?? $this->moduleConfigMock,
            $this->sspBridgeMock,
        );
    }


    /**
     * @return array{resource: string, parameters: array}
     */
    protected function lastModuleUrlCall(): array
    {
        $this->assertNotEmpty($this->moduleUrlCalls, 'The module URL bridge was never called.');

        return $this->moduleUrlCalls[array_key_last($this->moduleUrlCalls)];
    }


    protected function lastResource(): string
    {
        return $this->lastModuleUrlCall()['resource'];
    }


    protected function lastParameters(): array
    {
        return $this->lastModuleUrlCall()['parameters'];
    }


    /**
     * The resource string the bridge is expected to receive: the module name, a slash, then the route.
     */
    protected function prefixed(string $path): string
    {
        return self::MODULE_NAME . '/' . $path;
    }


    /**
     * The assertion is a tautology -- `sut()` returns `Routes` or throws -- and it is the shape this
     * repository uses. What it pins is the second half: that constructing `Routes` with these
     * collaborators does not throw.
     */
    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(Routes::class, $this->sut());
    }

    /*****************************************************************************************************************
     * getModuleUrl()
     ****************************************************************************************************************/

    public function testPrefixesTheResourceWithTheModuleName(): void
    {
        $url = $this->sut()->getModuleUrl('some/resource');

        $this->assertSame($this->prefixed('some/resource'), $this->lastResource());
        $this->assertSame(self::BASE_URL . $this->prefixed('some/resource'), $url);
    }


    /**
     * The module name is read from the injected `ModuleConfig` on each call rather than resolved once.
     * `ModuleConfig::MODULE_NAME` is a final constant, so the name cannot in fact vary between
     * deployments; what this pins is that `Routes` asks its collaborator every time. A hardcoded `oidc`
     * fails every routing test in this file, since the fixture name is not `oidc`. The break this test
     * catches on its own is a resolve-once cache, such as a static, which would answer a second instance
     * with the first instance's module name. The first call below primes such a cache within this
     * test rather than relying on an earlier one to have done it, so the test says the same thing
     * run on its own, under `--filter`, or in a randomised order.
     */
    public function testTakesTheModuleNameFromTheConfiguration(): void
    {
        $this->sut()->urlAuthorization();

        $this->assertSame($this->prefixed('authorization'), $this->lastResource());

        $renamedModuleConfig = $this->createMock(ModuleConfig::class);
        $renamedModuleConfig->method('moduleName')->willReturn('renamed-module');

        $this->sut($renamedModuleConfig)->urlAuthorization();

        $this->assertSame('renamed-module/authorization', $this->lastResource());
    }


    public function testAnEmptyResourceBecomesTheModuleRoot(): void
    {
        $url = $this->sut()->getModuleUrl();

        $this->assertSame(self::MODULE_NAME . '/', $this->lastResource());
        $this->assertSame(self::BASE_URL . self::MODULE_NAME . '/', $url);
    }


    public function testPassesParametersToTheBridgeUnchanged(): void
    {
        $parameters = ['ui_locales' => 'en', 'nested' => ['a', 'b'], 'zero' => 0];

        $this->sut()->getModuleUrl('some/resource', $parameters);

        $this->assertSame($parameters, $this->lastParameters());
    }

    /*****************************************************************************************************************
     * Route tables.
     ****************************************************************************************************************/

    /**
     * Every `url*()` method which takes nothing but a parameter array, paired with the path it must build.
     */
    public static function parameterlessUrlMethodProvider(): array
    {
        $routes = [
            'urlAdminConfigGeneral' => 'admin/config/general',
            'urlAdminConfigProtocol' => 'admin/config/protocol',
            'urlAdminConfigFederation' => 'admin/config/federation',
            'urlAdminMigrations' => 'admin/migrations',
            'urlAdminMigrationsRun' => 'admin/migrations/run',
            'urlAdminClients' => 'admin/clients',
            'urlAdminClientsAdd' => 'admin/clients/add',
            'urlAdminCredentialStatus' => 'admin/credential-status',
            'urlAdminCredentialStatusChange' => 'admin/credential-status/change',
            'urlAdminTestTrustChainResolution' => 'admin/test/trust-chain-resolution',
            'urlAdminTestTrustMarkValidation' => 'admin/test/trust-mark-validation',
            'urlAdminTestFederationDiscovery' => 'admin/test/federation-discovery',
            'urlAdminTestVerifiableCredentialIssuance' => 'admin/test/verifiable-credential-issuance',
            'urlOAuth2Configuration' => '.well-known/oauth-authorization-server',
            'urlConfiguration' => '.well-known/openid-configuration',
            'urlAuthorization' => 'authorization',
            'urlToken' => 'token',
            'urlUserInfo' => 'userinfo',
            'urlJwks' => 'jwks',
            'urlEndSession' => 'end-session',
            'urlRegistration' => 'register',
            'urlFederationConfiguration' => '.well-known/openid-federation',
            'urlPushedAuthorizationRequest' => 'par',
            'urlCredentialIssuerConfiguration' => '.well-known/openid-credential-issuer',
            'urlCredentialIssuerCredential' => 'credential-issuer/credential',
            'urlCredentialIssuerNonce' => 'credential-issuer/nonce',
            'urlJwtVcIssuerConfiguration' => '.well-known/jwt-vc-issuer',
            'urlVciDidDocument' => 'did.json',
            'urlApiVciCredentialOffer' => 'api/vci/credential-offer',
            'urlApiVciCredentialStatus' => 'api/vci/credential-status',
            'urlApiOAuth2TokenIntrospection' => 'api/oauth2/token-introspection',
        ];

        $rows = [];

        foreach ($routes as $method => $path) {
            $rows[$method] = [$method, $path];
        }

        return $rows;
    }


    /**
     * Each row is called twice: once with no arguments, which exercises the parameter default, and once
     * with a parameter array, which catches a wrapper that drops what its caller passed.
     */
    #[DataProvider('parameterlessUrlMethodProvider')]
    public function testParameterlessUrlMethodTargetsItsOwnRoute(string $method, string $path): void
    {
        $sut = $this->sut();

        $this->assertSame(self::BASE_URL . $this->prefixed($path), $sut->$method());
        $this->assertSame($this->prefixed($path), $this->lastResource());
        $this->assertSame([], $this->lastParameters());

        $sut->$method(['ui_locales' => 'en']);

        $this->assertSame($this->prefixed($path), $this->lastResource());
        $this->assertSame(['ui_locales' => 'en'], $this->lastParameters());
    }


    /**
     * The `url*()` methods which take a client ID and put it into the query parameters.
     */
    public static function clientIdUrlMethodProvider(): array
    {
        $routes = [
            'urlAdminClientsShow' => 'admin/clients/show',
            'urlAdminClientsEdit' => 'admin/clients/edit',
            'urlAdminClientsResetSecret' => 'admin/clients/reset-secret',
            'urlAdminClientsDelete' => 'admin/clients/delete',
        ];

        $rows = [];

        foreach ($routes as $method => $path) {
            $rows[$method] = [$method, $path];
        }

        return $rows;
    }


    /**
     * The parameter name is asserted as the literal `client_id` rather than through `ParametersEnum`,
     * because it is what the admin templates put into the `href` and form `action` attributes they
     * render, so renaming it changes URLs which are already in circulation.
     */
    #[DataProvider('clientIdUrlMethodProvider')]
    public function testClientIdUrlMethodCarriesTheClientId(string $method, string $path): void
    {
        $url = $this->sut()->$method(self::CLIENT_ID);

        $this->assertSame($this->prefixed($path), $this->lastResource());
        $this->assertSame(['client_id' => self::CLIENT_ID], $this->lastParameters());
        $this->assertSame(
            self::BASE_URL . $this->prefixed($path) . '?client_id=' . self::CLIENT_ID,
            $url,
        );
    }


    #[DataProvider('clientIdUrlMethodProvider')]
    public function testClientIdUrlMethodKeepsCallerSuppliedParameters(string $method, string $path): void
    {
        $this->sut()->$method(self::CLIENT_ID, ['ui_locales' => 'en']);

        $this->assertSame($this->prefixed($path), $this->lastResource());
        $this->assertSame(
            ['ui_locales' => 'en', 'client_id' => self::CLIENT_ID],
            $this->lastParameters(),
        );
    }


    /**
     * Current behaviour, pinned so a change to it is deliberate: the argument wins over a `client_id`
     * already present in the parameter array, rather than the array overriding the argument.
     */
    #[DataProvider('clientIdUrlMethodProvider')]
    public function testClientIdUrlMethodOverwritesACallerSuppliedClientId(string $method, string $path): void
    {
        $this->sut()->$method(self::CLIENT_ID, ['client_id' => 'other-client-id']);

        $this->assertSame($this->prefixed($path), $this->lastResource());
        $this->assertSame(['client_id' => self::CLIENT_ID], $this->lastParameters());
    }


    /**
     * The `url*()` methods which substitute an identifier into a path template, with the whole
     * template. The fixed part of the path is derived from it rather than written out a second time,
     * so the two cannot drift apart, and the enum guard below can compare whole route values the
     * way it does for every other table.
     */
    public static function placeholderUrlMethodProvider(): array
    {
        $routes = [
            'urlStatusList' => 'statuslist/{statusListId}',
            'urlCredentialJsonLdContext' => 'credential-issuer/context/{credentialConfigurationId}',
        ];

        $rows = [];

        foreach ($routes as $method => $template) {
            $rows[$method] = [$method, $template];
        }

        return $rows;
    }


    /**
     * The part of a route template which precedes its placeholder.
     */
    protected static function fixedPathPartOf(string $template): string
    {
        return substr($template, 0, (int)strpos($template, '{'));
    }


    #[DataProvider('placeholderUrlMethodProvider')]
    public function testPlaceholderUrlMethodSubstitutesTheIdentifier(
        string $method,
        string $template,
    ): void {
        $prefix = self::fixedPathPartOf($template);

        $url = $this->sut()->$method('identifier-1', ['ui_locales' => 'en']);

        $this->assertSame($this->prefixed($prefix . 'identifier-1'), $this->lastResource());
        $this->assertSame(['ui_locales' => 'en'], $this->lastParameters());
        $this->assertSame(
            self::BASE_URL . $this->prefixed($prefix . 'identifier-1') . '?ui_locales=en',
            $url,
        );
    }


    /**
     * Identifiers which do not survive being dropped into a path unescaped.
     *
     * One row carries both a space and a tilde, which is what separates `rawurlencode()` from
     * `urlencode()`: the first renders a space as `%20` and leaves `~` alone, the second writes `+`
     * and `%7E`. They share a row because a tilde on its own cannot have a row of its own here --
     * `rawurlencode()` leaves `~` untouched, so the row would read `['a~b', 'a~b']`, whose expectation
     * equals its input; it would pass with no encoding at all and would hide two columns which had
     * been crossed. Adding the space fixes that, and then a space-only row would test nothing this
     * one does not. An identifier of nothing but letters and digits would pass under either encoding,
     * and under none, so it would test nothing here either.
     * The slash row is the one with a consequence beyond the cosmetic: an unescaped identifier would end
     * the path segment and address a different route. It does not separate `rawurlencode()` from
     * `urlencode()`, which both escape a slash -- it fails when the encoding is dropped altogether.
     */
    public static function placeholderEncodingProvider(): array
    {
        $identifiers = [
            'slash' => ['a/../b', 'a%2F..%2Fb'],
            'space and tilde' => ['a~b c', 'a~b%20c'],
            'plus' => ['a+b', 'a%2Bb'],
            'question mark' => ['a?b', 'a%3Fb'],
            'hash' => ['a#b', 'a%23b'],
            'percent' => ['a%b', 'a%25b'],
            'ampersand' => ['a&b', 'a%26b'],
        ];

        $rows = [];

        foreach (self::placeholderUrlMethodProvider() as [$method, $template]) {
            $prefix = self::fixedPathPartOf($template);

            foreach ($identifiers as $label => [$identifier, $encoded]) {
                $rows[$method . ', ' . $label] = [$method, $prefix, $identifier, $encoded];
            }
        }

        return $rows;
    }


    #[DataProvider('placeholderEncodingProvider')]
    public function testPlaceholderUrlMethodEncodesTheIdentifier(
        string $method,
        string $prefix,
        string $identifier,
        string $encoded,
    ): void {
        $url = $this->sut()->$method($identifier);

        $this->assertSame($this->prefixed($prefix . $encoded), $this->lastResource());
        $this->assertSame([], $this->lastParameters());
        $this->assertSame(self::BASE_URL . $this->prefixed($prefix . $encoded), $url);
    }


    /**
     * Each templated method is handed its own placeholder token as the identifier: the value most
     * easily confused with the template it is being substituted into. It is encoded like any other,
     * so the braces arrive as `%7B` and `%7D`.
     *
     * There is no re-substitution hazard behind this. `str_replace()` with string arguments makes
     * one left-to-right pass and does not rescan what it inserted, so even an unencoded token could
     * not trigger a second substitution. What the encoding prevents is narrower: without it the
     * path would carry a literal `{statusListId}` and read as a template nobody had filled in.
     */
    public function testPlaceholderUrlMethodEncodesAnIdentifierWhichLooksLikeItsToken(): void
    {
        $this->sut()->urlStatusList('{statusListId}');

        $this->assertSame(
            $this->prefixed('statuslist/%7BstatusListId%7D'),
            $this->lastResource(),
        );

        $this->sut()->urlCredentialJsonLdContext('{credentialConfigurationId}');

        $this->assertSame(
            $this->prefixed('credential-issuer/context/%7BcredentialConfigurationId%7D'),
            $this->lastResource(),
        );
    }


    /**
     * Reflects over the class so a `url*()` method added later without a table row fails here rather than
     * arriving with no test at all.
     */
    public function testEveryUrlMethodIsCoveredByOneOfTheTables(): void
    {
        $tabled = array_merge(
            array_column(self::parameterlessUrlMethodProvider(), 0),
            array_column(self::clientIdUrlMethodProvider(), 0),
            array_column(self::placeholderUrlMethodProvider(), 0),
        );
        sort($tabled);

        $declared = [];

        foreach ((new ReflectionClass(Routes::class))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
            if (str_starts_with($method->getName(), 'url')) {
                $declared[] = $method->getName();
            }
        }

        sort($declared);

        $this->assertSame($declared, $tabled);
    }


    /**
     * The tables above are keyed by method; this checks the same ground from the enum side, so a
     * `RoutesEnum` case added without a `url*()` helper is noticed rather than quietly left to callers to
     * build from the enum value themselves.
     *
     * `AdminConfigVerifiableCredential` is the standing exception: the one case with no `url*()`
     * method of its own. `TemplateFactory` builds its admin menu link by passing the case value to
     * `getModuleUrl()`, which is how all eleven of that menu's links are built, helper or not, and
     * `ConfigController` passes the same value to the template factory as the active route. Naming
     * the case here records the one inconsistency and keeps a second from arriving unremarked.
     */
    public function testEveryRouteHasAUrlMethodExceptTheKnownOne(): void
    {
        // Whole route values, templates included. Matching only the fixed part of a template would
        // let a new case which happens to share that prefix pass as covered.
        $tabledPaths = array_merge(
            array_column(self::parameterlessUrlMethodProvider(), 1),
            array_column(self::clientIdUrlMethodProvider(), 1),
            array_column(self::placeholderUrlMethodProvider(), 1),
        );

        $missing = [];

        foreach (RoutesEnum::cases() as $case) {
            if (!in_array($case->value, $tabledPaths, true)) {
                $missing[] = $case->value;
            }
        }

        $this->assertSame(['admin/config/verifiable-credential'], $missing);
    }

    /*****************************************************************************************************************
     * Response factory methods.
     ****************************************************************************************************************/

    public function testNewRedirectResponseToModuleUrlPointsAtTheModuleUrl(): void
    {
        $response = $this->sut()->newRedirectResponseToModuleUrl('some/resource', ['ui_locales' => 'en']);

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame($this->prefixed('some/resource'), $this->lastResource());
        $this->assertSame(['ui_locales' => 'en'], $this->lastParameters());
        $this->assertSame(
            self::BASE_URL . $this->prefixed('some/resource') . '?ui_locales=en',
            $response->getTargetUrl(),
        );
    }


    public function testNewRedirectResponseToModuleUrlDefaultsToTheModuleRoot(): void
    {
        $response = $this->sut()->newRedirectResponseToModuleUrl();

        $this->assertSame(self::MODULE_NAME . '/', $this->lastResource());
        $this->assertSame([], $this->lastParameters());
        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame(self::BASE_URL . self::MODULE_NAME . '/', $response->getTargetUrl());
    }


    public function testNewRedirectResponseToModuleUrlPassesStatusAndHeaders(): void
    {
        $response = $this->sut()->newRedirectResponseToModuleUrl(
            'some/resource',
            [],
            303,
            ['X-Test' => 'test-value'],
        );

        $this->assertSame(303, $response->getStatusCode());
        $this->assertSame('test-value', $response->headers->get('X-Test'));
    }


    public function testNewResponseDefaultsToAnEmptyOkResponse(): void
    {
        $response = $this->sut()->newResponse();

        $this->assertInstanceOf(Response::class, $response);
        $this->assertSame('', $response->getContent());
        $this->assertSame(200, $response->getStatusCode());
    }


    public function testNewResponseTurnsNullContentIntoAnEmptyBody(): void
    {
        $this->assertSame('', $this->sut()->newResponse(null)->getContent());
    }


    public function testNewResponseTakesContentWithTheDefaultStatus(): void
    {
        $response = $this->sut()->newResponse('response-body');

        $this->assertSame('response-body', $response->getContent());
        $this->assertSame(200, $response->getStatusCode());
    }


    public function testNewResponsePassesContentStatusAndHeaders(): void
    {
        $response = $this->sut()->newResponse('response-body', 404, ['X-Test' => 'test-value']);

        $this->assertSame('response-body', $response->getContent());
        $this->assertSame(404, $response->getStatusCode());
        $this->assertSame('test-value', $response->headers->get('X-Test'));
    }


    public function testNewJsonResponseEncodesTheData(): void
    {
        $response = $this->sut()->newJsonResponse(['key' => 'value', 'number' => 1]);

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame('{"key":"value","number":1}', $response->getContent());
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('application/json', $response->headers->get('Content-Type'));
    }


    /**
     * Null and the empty array are not the same response body: null becomes an object and the empty array
     * stays an array, which is the difference between `{}` and `[]` on the wire.
     */
    public function testNewJsonResponseDistinguishesNullDataFromAnEmptyArray(): void
    {
        $this->assertSame('{}', $this->sut()->newJsonResponse()->getContent());
        $this->assertSame('{}', $this->sut()->newJsonResponse(null)->getContent());
        $this->assertSame('[]', $this->sut()->newJsonResponse([])->getContent());
    }


    public function testNewJsonResponsePassesStatusAndHeaders(): void
    {
        $response = $this->sut()->newJsonResponse(['key' => 'value'], 201, ['X-Test' => 'test-value']);

        $this->assertSame(201, $response->getStatusCode());
        $this->assertSame('test-value', $response->headers->get('X-Test'));
    }


    /**
     * The `$json` argument cannot be used as the method is declared. It tells `JsonResponse` the data is
     * already an encoded string, and `$data` here is typed `array|null`, so every value it accepts
     * raises a `TypeError` -- from `JsonResponse`'s own check, or failing that from the `string`
     * parameter of `setJson()` it would otherwise reach. What is pinned is that the argument cannot
     * be used, not which of the two raises.
     * No caller in the module passes the argument. Pinned so that widening the parameter type, which is
     * what would make it usable, is a deliberate change rather than an accident.
     */
    public function testNewJsonResponseCannotBeToldItsArrayDataIsAlreadyJson(): void
    {
        $this->expectException(TypeError::class);

        $this->sut()->newJsonResponse(['key' => 'value'], 200, [], true);
    }


    public function testNewJsonResponseCannotBeToldItsNullDataIsAlreadyJson(): void
    {
        $this->expectException(TypeError::class);

        $this->sut()->newJsonResponse(null, 200, [], true);
    }


    /**
     * The key names are the OAuth 2.0 error response fields, so they are asserted as literal strings.
     * The default status is 500, which is the one an error response gets when a caller does not say.
     */
    public function testNewJsonErrorResponseUsesTheOAuth2ErrorShape(): void
    {
        $response = $this->sut()->newJsonErrorResponse('invalid_request', 'Something was wrong.');

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(
            '{"error":"invalid_request","error_description":"Something was wrong."}',
            $response->getContent(),
        );
        $this->assertSame(500, $response->getStatusCode());
        $this->assertSame('application/json', $response->headers->get('Content-Type'));
    }


    public function testNewJsonErrorResponsePassesTheHttpCodeAndHeaders(): void
    {
        $response = $this->sut()->newJsonErrorResponse(
            'invalid_client',
            'Client authentication failed.',
            401,
            ['WWW-Authenticate' => 'Basic realm="OIDC"'],
        );

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('Basic realm="OIDC"', $response->headers->get('WWW-Authenticate'));
    }


    /**
     * Several callers pass an exception message as the description -- the credential status, credential
     * offer and token introspection controllers all do -- so what reaches the body is not fixed at the
     * call site. The encoding therefore has to escape the characters which would matter if the body were
     * rendered as HTML or embedded in a script. That is `JsonResponse`'s default encoding, which this
     * factory gets by handing it the data to encode; building the response from an already encoded
     * string would skip it.
     */
    public function testNewJsonErrorResponseEscapesHtmlSensitiveCharacters(): void
    {
        $description = '<script>alert(document.cookie)&\'"</script>';

        $content = (string)$this->sut()->newJsonErrorResponse('invalid_request', $description)->getContent();

        foreach (['<', '>', '&', "'"] as $character) {
            $this->assertStringNotContainsString($character, $content);
        }

        // The double quote cannot be searched for the same way, since it delimits every string in
        // the document, so its escape is asserted present instead. `JSON_HEX_QUOT` writes the hex
        // form; without that option the quote is merely backslash escaped, which is still valid
        // JSON and decodes cleanly, so the round trip below would not notice. chr(92) is the
        // backslash the literal would otherwise need.
        $this->assertStringContainsString(chr(92) . 'u0022', $content);

        // Escaped, not dropped: the description still decodes back to exactly what was passed in.
        $this->assertSame(
            ['error' => 'invalid_request', 'error_description' => $description],
            json_decode($content, true),
        );
    }
}
