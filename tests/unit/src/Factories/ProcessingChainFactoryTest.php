<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Module\oidc\Factories\ProcessingChainFactory;

/**
 * @covers \SimpleSAML\Module\oidc\Factories\ProcessingChainFactory
 */
#[AllowMockObjectsWithoutExpectations]
class ProcessingChainFactoryTest extends TestCase
{
    final public const string URI = 'https://some-server/authorize.php?abc=efg';

    final public const string AUTH_SOURCE = 'auth_source';

    final public const string USER_ID_ATTR = 'uid';

    final public const string USERNAME = 'username';

    final public const array OIDC_OP_METADATA = ['issuer' => 'https://idp.example.org'];

    final public const array USER_ENTITY_ATTRIBUTES = [
        self::USER_ID_ATTR    => [self::USERNAME],
        'eduPersonTargetedId' => [self::USERNAME],
    ];

    final public const array AUTH_DATA = ['Attributes' => self::USER_ENTITY_ATTRIBUTES];

    final public const array CLIENT_ENTITY = ['id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];

    final public const array AUTHZ_REQUEST_PARAMS = [
        'client_id' => 'clientid',
        'redirect_uri' => 'https://rp.example.org',
    ];

    /**
     * The factory consumes the IdP / SP metadata (entityid + authproc) that
     * AuthenticationService::runAuthProcs() has already prepared in the state.
     */
    final public const array STATE = [
        'Attributes' => self::AUTH_DATA['Attributes'],
        'Oidc'       => [
            'OpenIdProviderMetadata'         => self::OIDC_OP_METADATA,
            'RelyingPartyMetadata'           => self::CLIENT_ENTITY,
            'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
        ],
        'Source'      => ['entityid' => 'https://idp.example.org', 'authproc' => []],
        'Destination' => ['entityid' => 'clientid', 'authproc' => []],
    ];


    /**
     * @return \SimpleSAML\Module\oidc\Factories\ProcessingChainFactory
     */
    protected function prepareMockedInstance(): ProcessingChainFactory
    {
        return new ProcessingChainFactory();
    }


    /**
     * @return void
     */
    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(
            ProcessingChainFactory::class,
            $this->prepareMockedInstance(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testCanBuildProcessingChain(): void
    {
        $state = self::STATE;
        $this->assertInstanceOf(
            ProcessingChain::class,
            $this->prepareMockedInstance()->build($state),
        );
    }
}
