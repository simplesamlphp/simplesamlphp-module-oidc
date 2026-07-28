<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Federation\TrustMark;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Twig\TwigFilter;

/**
 * Renders the configuration overview templates against real view model objects, so that a mismatch
 * between the builder and the templates (renamed getter, new value type without a rendering branch)
 * fails here instead of on the admin screen.
 *
 * A bare Twig environment is used, with the SimpleSAMLphp specific 'trans' filter stubbed out.
 * Strict variables are enabled so that unknown properties are errors rather than empty output.
 */
#[CoversNothing]
class OverviewTemplateRenderTest extends TestCase
{
    use OverviewTestTrait;
    use ProtocolOverviewTestTrait;
    use FederationOverviewTestTrait;

    protected function twig(): Environment
    {
        $loader = new FilesystemLoader();
        $loader->addPath(dirname(__DIR__, 5) . '/templates', 'oidc');

        $twig = new Environment($loader, ['strict_variables' => true]);
        $twig->addFilter(new TwigFilter('trans', fn(mixed $value): mixed => $value));

        return $twig;
    }

    /**
     * @throws \Exception
     */
    protected function render(array $overrides = []): string
    {
        return $this->renderSections($this->buildProtocolOverviewBuilder($overrides)->build());
    }

    /**
     * @throws \Exception
     */
    protected function renderFederation(array $overrides = [], array $trustMarks = []): string
    {
        return $this->renderSections(
            $this->buildFederationOverviewBuilder($overrides)->build($trustMarks),
        );
    }

    /**
     * @param \SimpleSAML\Module\oidc\Admin\ConfigOverview\Section[] $sections
     * @throws \Exception
     */
    protected function renderSections(array $sections): string
    {
        return $this->twig()->render(
            '@oidc/config/includes/overview-sections.twig',
            ['sections' => $sections],
        );
    }

    /**
     * @throws \Exception
     */
    public function testCanRenderAllSections(): void
    {
        $html = $this->render();

        $this->assertNotEmpty($html);

        foreach ($this->buildProtocolOverviewBuilder()->build() as $section) {
            $this->assertStringContainsString('id="' . $section->getAnchor() . '"', $html);
            $this->assertStringContainsString($section->getTitle(), $html);
        }
    }

    /**
     * @throws \Exception
     */
    public function testRendersTextAndDurationValues(): void
    {
        $html = $this->render();

        $this->assertStringContainsString('http://test.issuer', $html);
        $this->assertStringContainsString('10 minutes (PT10M)', $html);
    }

    /**
     * @throws \Exception
     */
    public function testRendersUrlValuesAsLinks(): void
    {
        $this->assertStringContainsString('rel="noopener noreferrer"', $this->render());
    }

    /**
     * @throws \Exception
     */
    public function testRendersStringListValues(): void
    {
        $html = $this->render([ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE => ['eduPersonPrincipalName']]);

        $this->assertStringContainsString('<li>eduPersonPrincipalName</li>', $html);
    }

    /**
     * @throws \Exception
     */
    public function testRendersStringMapValues(): void
    {
        $html = $this->render([
            ModuleConfig::OPTION_AUTH_ACR_VALUES_SUPPORTED => ['1', '0'],
            ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP => ['example-userpass' => ['1', '0']],
        ]);

        $this->assertStringContainsString('example-userpass', $html);
    }

    /**
     * @throws \Exception
     */
    public function testRendersScopeValues(): void
    {
        $html = $this->render([
            ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES => [
                'private' => [
                    'description' => 'private scope',
                    'claim_name_prefix' => 'prefix_',
                    'are_multiple_claim_values_allowed' => true,
                    'claims' => ['national_document_id'],
                ],
            ],
        ]);

        $this->assertStringContainsString('private', $html);
        $this->assertStringContainsString('private scope', $html);
        $this->assertStringContainsString('prefix_', $html);
        $this->assertStringContainsString('national_document_id', $html);
        // Standard scopes are shown too, with their origin marked.
        $this->assertStringContainsString('openid', $html);
    }

    /**
     * @throws \Exception
     */
    public function testRendersJsonValues(): void
    {
        $html = $this->render([
            ModuleConfig::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS => ['timeout' => 9],
        ]);

        $this->assertStringContainsString('code-box-content', $html);
        $this->assertStringContainsString('&quot;timeout&quot;', $html);
    }

    /**
     * @throws \Exception
     */
    public function testRendersWarnings(): void
    {
        $html = $this->render([
            ModuleConfig::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS => ['verify' => false],
        ]);

        $this->assertStringContainsString('config-warning', $html);
        $this->assertStringContainsString('man-in-the-middle', $html);
    }

    /**
     * @throws \Exception
     */
    public function testRendersNotes(): void
    {
        $this->assertStringContainsString('config-note', $this->render());
    }

    /**
     * @throws \Exception
     */
    public function testRedactsCredentialsInHttpClientOptions(): void
    {
        $html = $this->render([
            ModuleConfig::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS => [
                'timeout' => 9,
                'auth' => ['api-user', 'super-secret-basic-password'],
                'headers' => ['Authorization' => 'Bearer super-secret-bearer-token'],
            ],
        ]);

        $this->assertStringNotContainsString('super-secret-basic-password', $html);
        $this->assertStringNotContainsString('super-secret-bearer-token', $html);
        $this->assertStringContainsString('not shown', $html);
        $this->assertStringContainsString('&quot;timeout&quot;', $html);
    }

    /**
     * @throws \Exception
     */
    public function testCanRenderAllFederationSections(): void
    {
        $html = $this->renderFederation();

        $this->assertNotEmpty($html);

        foreach ($this->buildFederationOverviewBuilder()->build() as $section) {
            $this->assertStringContainsString('id="' . $section->getAnchor() . '"', $html);
            $this->assertStringContainsString($section->getTitle(), $html);
        }
    }

    /**
     * @throws \Exception
     */
    public function testRendersTrustAnchorValues(): void
    {
        $html = $this->renderFederation([
            ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS => [
                'https://ta.example.org/' => '{"keys":[]}',
                'https://ta2.example.org/' => null,
            ],
        ]);

        $this->assertStringContainsString('https://ta.example.org/', $html);
        $this->assertStringContainsString('https://ta2.example.org/', $html);
        $this->assertStringContainsString('code-box-content', $html);
    }

    /**
     * @throws \Exception
     */
    public function testRendersTrustMarkValues(): void
    {
        $trustMark = $this->createMock(TrustMark::class);
        $trustMark->method('getTrustMarkType')->willReturn('https://ta.example.org/trust-mark-type');
        $trustMark->method('getPayload')->willReturn(['trust_mark_type' => 'https://ta.example.org/trust-mark-type']);

        $html = $this->renderFederation([], [$trustMark]);

        $this->assertStringContainsString('https://ta.example.org/trust-mark-type', $html);
        $this->assertStringContainsString('trust_mark_type', $html);
    }

    /**
     * The key pair bag is null when it could not be resolved, and the template must cope.
     *
     * @throws \Exception
     */
    public function testRendersSignatureKeyPairsWhenTheyCanNotBeResolved(): void
    {
        $html = $this->renderFederation([
            ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS => [],
        ]);

        $this->assertStringContainsString('Federation Signature Key Pairs', $html);
        $this->assertStringContainsString('config-warning', $html);
    }

    /**
     * @throws \Exception
     */
    public function testDoesNotRenderFederationSecrets(): void
    {
        $html = $this->renderFederation([
            ModuleConfig::OPTION_FEDERATION_TRUST_MARK_TOKENS => ['ey-super-secret-trust-mark-token'],
            ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER_ARGUMENTS => [
                'memcached://user:super-secret-password@localhost',
            ],
            ModuleConfig::OPTION_FEDERATION_HTTP_CLIENT_OPTIONS => [
                'auth' => ['user', 'super-secret-basic-password'],
            ],
        ]);

        $this->assertStringNotContainsString('ey-super-secret-trust-mark-token', $html);
        $this->assertStringNotContainsString('super-secret-password', $html);
        $this->assertStringNotContainsString('super-secret-basic-password', $html);
    }

    /**
     * @throws \Exception
     */
    public function testDoesNotRenderSecrets(): void
    {
        $html = $this->render([
            ModuleConfig::OPTION_ENCRYPTION_KEY => 'super-secret-encryption-key',
            ModuleConfig::OPTION_DCR_ENABLED => true,
            ModuleConfig::OPTION_DCR_INITIAL_ACCESS_TOKENS => ['super-secret-initial-access-token'],
            ModuleConfig::OPTION_API_ENABLED => true,
            ModuleConfig::OPTION_API_TOKENS => ['super-secret-api-token' => ['scope']],
            ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER_ARGUMENTS => [
                'memcached://user:super-secret-password@localhost',
            ],
        ]);

        $this->assertStringNotContainsString('super-secret-encryption-key', $html);
        $this->assertStringNotContainsString('super-secret-initial-access-token', $html);
        $this->assertStringNotContainsString('super-secret-api-token', $html);
        $this->assertStringNotContainsString('super-secret-password', $html);
    }
}
