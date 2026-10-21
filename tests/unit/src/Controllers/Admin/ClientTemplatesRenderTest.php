<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Admin;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Bridge\Twig\Extension\TranslationExtension;
use Twig\Environment;
use Twig\Loader\ArrayLoader;
use Twig\Loader\ChainLoader;
use Twig\Loader\FilesystemLoader;

/**
 * Renders the client list and the client page, to check that they offer no change to the VCI Generic Client, which
 * the module keeps rebuilding from its configuration (ClientController refuses such changes as well), while still
 * offering them for any other client.
 *
 * A one-block template stands in for the module's base template, which extends SimpleSAMLphp's page and so needs a
 * SimpleSAMLphp installation. Translation is Symfony's Twig extension, as in SimpleSAMLphp, with no translator, and
 * strict variables make a misspelled getter an error rather than empty output.
 */
#[CoversNothing]
#[AllowMockObjectsWithoutExpectations]
class ClientTemplatesRenderTest extends TestCase
{
    protected function twig(): Environment
    {
        $filesystemLoader = new FilesystemLoader();
        $filesystemLoader->addPath(dirname(__DIR__, 5) . '/templates', 'oidc');

        $twig = new Environment(
            new ChainLoader([
                new ArrayLoader(['@oidc/base.twig' => '{% block oidcContent %}{% endblock %}']),
                $filesystemLoader,
            ]),
            ['strict_variables' => true],
        );
        $twig->addExtension(new TranslationExtension());

        return $twig;
    }


    protected function routes(): Routes
    {
        $routes = $this->createStub(Routes::class);
        $routes->method('urlAdminClients')->willReturn('/clients');
        $routes->method('urlAdminClientsAdd')->willReturn('/clients/add');
        $routes->method('urlAdminClientsShow')->willReturnCallback(fn(string $id): string => '/show/' . $id);
        $routes->method('urlAdminClientsEdit')->willReturnCallback(fn(string $id): string => '/edit/' . $id);
        $routes->method('urlAdminClientsDelete')->willReturnCallback(fn(string $id): string => '/delete/' . $id);
        $routes->method('urlAdminClientsResetSecret')
            ->willReturnCallback(fn(string $id): string => '/reset-secret/' . $id);

        return $routes;
    }


    protected function client(string $identifier, bool $isGeneric): ClientEntity
    {
        return new ClientEntity(
            identifier: $identifier,
            secret: 'secret',
            name: 'Name',
            description: 'Description',
            redirectUri: ['https://rp.example.org/callback'],
            scopes: ['openid'],
            isEnabled: true,
            isGeneric: $isGeneric,
        );
    }


    /**
     * @param array<string,mixed>|false|null $clientAttestationTrust As ClientController::show() describes it.
     */
    protected function renderClientPage(
        ClientEntity $client,
        array|false|null $clientAttestationTrust = null,
    ): string {
        return $this->twig()->render(
            '@oidc/clients/show.twig',
            [
                'client' => $client,
                'allowedOrigins' => [],
                'setsGivenSecret' => true,
                'routes' => $this->routes(),
                'clientAttestationTrust' => $clientAttestationTrust,
            ],
        );
    }


    public function testTheClientPageShowsTheClientAttestationTrust(): void
    {
        $html = $this->renderClientPage($this->client('wallet', false), [
            'attester' => 'https://wallet-provider.example.org',
            'issuingCaPublicKeySha256' => 'oK0aZlY8bQfkRFIkV3WdWDiLT_7WWqv0eXhTYGOE7wE',
            'attesterIdentityType' => 'san_dns',
            'attesterIdentity' => 'wallet-provider.example.org',
            'trustAnchors' => ['cn=Wallet Root CA (valid until 2030-01-01 12:00 UTC)'],
        ]);

        $this->assertStringContainsString('https://wallet-provider.example.org', $html);
        $this->assertStringContainsString('oK0aZlY8bQfkRFIkV3WdWDiLT_7WWqv0eXhTYGOE7wE', $html);
        $this->assertStringContainsString('san_dns wallet-provider.example.org', $html);
        $this->assertStringContainsString('cn=Wallet Root CA (valid until 2030-01-01 12:00 UTC)', $html);
    }


    public function testTheClientPageSaysWhenTheClientAttestationTrustCanNotBeRead(): void
    {
        $this->assertStringContainsString(
            'The attestation trust stored for this Client can not be read.',
            $this->renderClientPage($this->client('wallet', false), false),
        );
        $this->assertStringContainsString(
            'The trust anchors can not be read.',
            $this->renderClientPage($this->client('wallet', false), [
                'attester' => 'https://wallet-provider.example.org',
                'issuingCaPublicKeySha256' => 'oK0aZlY8bQfkRFIkV3WdWDiLT_7WWqv0eXhTYGOE7wE',
                'attesterIdentityType' => 'san_dns',
                'attesterIdentity' => 'wallet-provider.example.org',
                'trustAnchors' => null,
            ]),
        );
    }


    public function testTheGenericClientsPageOffersNoChangeAndSaysWhy(): void
    {
        $html = $this->renderClientPage($this->client('vci_generic', true));

        $this->assertStringContainsString('href="/clients"', $html);
        $this->assertStringNotContainsString('/edit/vci_generic', $html);
        $this->assertStringNotContainsString('/delete/vci_generic', $html);
        $this->assertStringNotContainsString('name="secret"', $html);
        $this->assertStringContainsString('The module manages this client', $html);
    }


    public function testAnyOtherClientsPageOffersEditingAndDeletion(): void
    {
        $html = $this->renderClientPage($this->client('rp', false));

        $this->assertStringContainsString('href="/edit/rp"', $html);
        $this->assertStringContainsString('action="/delete/rp"', $html);
        $this->assertStringNotContainsString('The module manages this client', $html);
    }


    public function testTheClientListOffersNoChangeToTheGenericClientOnly(): void
    {
        $html = $this->twig()->render(
            '@oidc/clients.twig',
            [
                'clients' => [$this->client('vci_generic', true), $this->client('rp', false)],
                'numPages' => 1,
                'currentPage' => 1,
                'query' => '',
                'routes' => $this->routes(),
            ],
        );

        $this->assertStringContainsString('href="/show/vci_generic"', $html);
        $this->assertStringNotContainsString('/edit/vci_generic', $html);
        $this->assertStringNotContainsString('/delete/vci_generic', $html);
        $this->assertStringContainsString('href="/show/rp"', $html);
        $this->assertStringContainsString('href="/edit/rp"', $html);
        $this->assertStringContainsString('action="/delete/rp"', $html);
    }
}
