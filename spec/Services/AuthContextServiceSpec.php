<?php

namespace spec\SimpleSAML\Module\oidc\Services;

use PhpSpec\ObjectBehavior;
use RuntimeException;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Services\ConfigurationService;

class AuthContextServiceSpec extends ObjectBehavior
{
    public const AUTHORIZED_USER = [
        'idAttribute' => ['myUsername'],
        'someEntitlement' => ['val1', 'val2', 'val3']
    ];

    public function let(
        AuthSimpleFactory $authSimpleFactory,
        Simple $simple,
        ConfigurationService $configurationService,
        Configuration $oidcConfiguration
    ): void {
        $oidcConfiguration->getString('useridattr')->willReturn('idAttribute');
        $configurationService->getOpenIDConnectConfiguration()->willReturn($oidcConfiguration);
        $simple->requireAuth()->shouldBeCalledOnce();
        $simple->getAttributes()->willReturn(self::AUTHORIZED_USER);
        $authSimpleFactory->getDefaultAuthSource()->willReturn($simple);
        $permssions = Configuration::loadFromArray(
            [
                // Attribute to inspect to determine user's permissions
                'attribute' => 'someEntitlement',
                // Entitlements allow for registering, editing, delete a client. OIDC clients are owned by the creator
                'client' => ['val2'],
            ]
        );
        $oidcConfiguration->getOptionalConfigItem('permissions', null)->willReturn($permssions);
        $this->beConstructedWith(
            $configurationService,
            $authSimpleFactory
        );
    }

    public function it_returns_username()
    {
        $this->getAuthUserId()->shouldEqual('myUsername');
    }

    public function it_errors_when_no_username(Configuration $oidcConfiguration)
    {
        $oidcConfiguration->getString('useridattr')->willReturn('attributeNotSet');
        $this->shouldThrow(\SimpleSAML\Error\Exception::class)->during('getAuthUserId');
    }

    public function it_is_authorized_by_entitlement()
    {
        $this->requirePermission('client');
    }

    public function it_is_not_authorized_for_permission()
    {
        $this->shouldThrow(new RuntimeException('No permission defined for no-match'))
            ->duringRequirePermission('no-match');
    }

    public function it_has_wrong_entitlements(Simple $simple)
    {
        $simple->getAttributes()->willReturn([
            'idAttribute' => ['myUsername'],
            'someEntitlement' =>  ['otherEntitlement']
                                                 ]);
        $this->shouldThrow(new RuntimeException('Missing entitlement for client'))
            ->duringRequirePermission('client');
    }

    public function it_has_no_entitlment_attribute(Simple $simple)
    {
        $simple->getAttributes()->willReturn([
                                                 'idAttribute' => ['myUsername'],
                                             ]);
        $this->shouldThrow(new RuntimeException('Missing entitlement for client'))
            ->duringRequirePermission('client');
    }

    public function it_has_no_enable_permissions(Configuration $oidcConfiguration)
    {
        $permssions = Configuration::loadFromArray([]);
        $oidcConfiguration->getOptionalConfigItem('permissions', null)->willReturn($permssions);
        $this->shouldThrow(new RuntimeException('Permissions not enabled'))->duringRequirePermission('client');
    }
}
