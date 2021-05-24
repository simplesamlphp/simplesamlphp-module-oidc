<?php

namespace spec\SimpleSAML\Modules\OpenIDConnect\Services;

use PhpSpec\ObjectBehavior;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;
use SimpleSAML\Modules\OpenIDConnect\Services\OidcOpenIdProviderMetadataService;

class OidcOpenIdProviderMetadataServiceSpec extends ObjectBehavior
{
    public function let(
        ConfigurationService $configurationService
    ): void {
        $configurationService->getOpenIDScopes()->shouldBeCalled()
            ->willReturn(['openid' => 'openid']);

        $configurationService->getSimpleSAMLSelfURLHost()->shouldBeCalled()
            ->willReturn('http://localhost');
        $configurationService->getOpenIdConnectModuleURL('authorize.php')
            ->willReturn('http://localhost/authorize.php');
        $configurationService->getOpenIdConnectModuleURL('access_token.php')
            ->willReturn('http://localhost/access_token.php');
        $configurationService->getOpenIdConnectModuleURL('userinfo.php')
            ->willReturn('http://localhost/userinfo.php');
        $configurationService->getOpenIdConnectModuleURL('jwks.php')
            ->willReturn('http://localhost/jwks.php');

        $this->beConstructedWith($configurationService);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(OidcOpenIdProviderMetadataService::class);
    }

    public function it_returns_expected_metadata(): void
    {
        $this->getMetadata()->shouldBe([
            'issuer' => 'http://localhost',
            'authorization_endpoint' => 'http://localhost/authorize.php',
            'token_endpoint' => 'http://localhost/access_token.php',
            'userinfo_endpoint' => 'http://localhost/userinfo.php',
            'jwks_uri' => 'http://localhost/jwks.php',
            'scopes_supported' => ['openid'],
            'response_types_supported' => ['code', 'token'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['plain', 'S256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic'],
            'request_parameter_supported' => false,
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
        ]);
    }
}
