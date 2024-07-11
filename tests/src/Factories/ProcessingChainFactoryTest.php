<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Factories;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Module\oidc\Factories\ProcessingChainFactory;
use SimpleSAML\Module\oidc\ModuleConfig;

/**
 * @covers \SimpleSAML\Module\oidc\Factories\ProcessingChainFactory
 */
class ProcessingChainFactoryTest extends TestCase
{
    final public const URI = 'https://some-server/authorize.php?abc=efg';
    final public const AUTH_SOURCE = 'auth_source';
    final public const USER_ID_ATTR = 'uid';
    final public const USERNAME = 'username';
    final public const OIDC_OP_METADATA = ['issuer' => 'https://idp.example.org'];
    final public const USER_ENTITY_ATTRIBUTES = [
        self::USER_ID_ATTR    => [self::USERNAME],
        'eduPersonTargetedId' => [self::USERNAME],
    ];
    final public const AUTH_DATA = ['Attributes' => self::USER_ENTITY_ATTRIBUTES];
    final public const CLIENT_ENTITY = ['id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];
    final public const AUTHZ_REQUEST_PARAMS = ['client_id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];
    final public const STATE = [
        'Attributes' => self::AUTH_DATA['Attributes'],
        'Oidc'       => [
            'OpenIdProviderMetadata'         => self::OIDC_OP_METADATA,
            'RelyingPartyMetadata'           => self::CLIENT_ENTITY,
            'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
        ],
    ];

    /**
     * @var MockObject|(object&MockObject)|ModuleConfig|(ModuleConfig&object&MockObject)|(ModuleConfig&MockObject)
     */
    protected MockObject $moduleConfigMock;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
    }

    /**
     * @return ProcessingChainFactory
     */
    protected function prepareMockedInstance(): ProcessingChainFactory
    {
        return new ProcessingChainFactory($this->moduleConfigMock);
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
