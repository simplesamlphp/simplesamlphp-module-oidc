<?php

namespace spec\SimpleSAML\Modules\OpenIDConnect\Factories;

use PhpSpec\ObjectBehavior;
use SimpleSAML\Configuration;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;

class ClaimTranslatorExtractorFactorySpec extends ObjectBehavior
{

    public function it_sets_private_scope_prefixes_and_types(ConfigurationService $configurationService)
    {
        $configurationService->getOpenIDConnectConfiguration()->willReturn(
            Configuration::loadFromArray(
                [
                    'translate' => [
                        'testClaim' => ['attribute'],
                        'int:intClaim' => ['intAttribute'],
                        'testClaim2' => ['attribute2'],
                        'bool:boolClaim' => ['boolAttribute'],
                    ]
                ]
            )
        );
        $configurationService->getOpenIDPrivateScopes()->willReturn(
            [
                'customScope1' => [
                    'attributes' => ['testClaim', 'intClaim']
                ],
                'customScope2' => [
                    'attributes' => ['testClaim2', 'boolClaim'],
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
