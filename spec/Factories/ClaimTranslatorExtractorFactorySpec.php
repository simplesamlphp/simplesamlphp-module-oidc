<?php

namespace spec\SimpleSAML\Module\oidc\Factories;

use PhpSpec\ObjectBehavior;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Services\ConfigurationService;

class ClaimTranslatorExtractorFactorySpec extends ObjectBehavior
{
    public function it_sets_private_scope_prefixes_and_types(ConfigurationService $configurationService)
    {
        $configurationService->getOpenIDConnectConfiguration()->willReturn(
            Configuration::loadFromArray(
                [
                    'useridattr' => 'uid',
                    'translate' => [
                        'testClaim' => ['attribute'],
                        'intClaim' => [
                            'type' => 'int',
                            'intAttribute'
                        ],
                        'testClaim2' => ['attribute2'],
                        'boolClaim' => [
                            'type' => 'bool',
                            'attributes' => ['boolAttribute']
                        ],
                    ]
                ]
            )
        );
        $configurationService->getOpenIDPrivateScopes()->willReturn(
            [
                'customScope1' => [
                    'claims' => ['testClaim', 'intClaim']
                ],
                'customScope2' => [
                    'claims' => ['testClaim2', 'boolClaim'],
                    'claim_name_prefix' => 'myprefix_'
                ]

            ]
        );
        $this->beConstructedWith($configurationService);

        $claimTranslater = $this->build();
        $claimTranslater->getClaimSet('customScope2')->getClaims()
            ->shouldEqual(['myprefix_testClaim2', 'myprefix_boolClaim']);
        $claimData = $claimTranslater->extract(['openid', 'email', 'profile', 'customScope1', 'customScope2'], [
            'cn' => ['Firsty Lasty'],
            'attribute' => ['val1'],
            'intAttribute' => ['56789'],
            'boolAttribute' => ['yes'],
            'attribute2' => ['val2']
        ]);

        $claimData->shouldHaveKeyWithValue('name', 'Firsty Lasty');
        $claimData->shouldHaveKeyWithValue('testClaim', 'val1');
        $claimData->shouldHaveKeyWithValue('intClaim', 56789);
        $claimData->shouldHaveKeyWithValue('myprefix_testClaim2', 'val2');
        $claimData->shouldHaveKeyWithValue('myprefix_boolClaim', true);
    }
}
