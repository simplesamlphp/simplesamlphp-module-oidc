<?php

namespace SimpleSAML\Test\Module\oidc\Factories;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Factories\ClaimTranslatorExtractorFactory;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;

/**
 * @covers \SimpleSAML\Module\oidc\Factories\ClaimTranslatorExtractorFactory
 */
class ClaimTranslatorExtractorFactoryTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $configurationServiceMock;

    protected function setUp(): void
    {
        $this->configurationServiceMock = $this->createMock(ConfigurationService::class);
        $this->configurationServiceMock
            ->method('getOpenIDConnectConfiguration')
            ->willReturn(
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
        $this->configurationServiceMock
            ->method('getOpenIDPrivateScopes')
            ->willReturn(
                [
                    'customScope1' => [
                        'claims' => ['testClaim', 'intClaim'],
                    ],
                    'customScope2' => [
                        'claims' => ['testClaim2', 'boolClaim'],
                        'claim_name_prefix' => 'myprefix_',
                    ],
                    'customScope3' => [
                        'claims' => ['testClaim3', 'boolClaim'],
                        'are_multiple_claim_values_allowed' => true,
                    ],
                ]
            );
    }

    protected function prepareMockedInstance(): ClaimTranslatorExtractorFactory
    {
        return new ClaimTranslatorExtractorFactory($this->configurationServiceMock);
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(
            ClaimTranslatorExtractorFactory::class,
            $this->prepareMockedInstance()
        );
    }

    public function testCanBuildClaimTranslatorExtractor(): void
    {
        $this->assertInstanceOf(
            ClaimTranslatorExtractor::class,
            $this->prepareMockedInstance()->build()
        );
    }

    public function testExtractor(): void
    {
        $claimTranslatorExtractor = $this->prepareMockedInstance()->build();

        $this->assertSame(
            $claimTranslatorExtractor->getClaimSet('customScope2')->getClaims(),
            ['myprefix_testClaim2', 'myprefix_boolClaim']
        );

        $claimData = $claimTranslatorExtractor->extract(
            ['openid', 'email', 'profile', 'customScope1', 'customScope2'],
            [
                'cn' => ['Firsty Lasty'],
                'attribute' => ['val1'],
                'intAttribute' => ['56789'],
                'boolAttribute' => ['yes'],
                'attribute2' => ['val2']
            ]
        );

        $this->assertSame(
            $claimData,
            [
                'name' => "Firsty Lasty",
                'testClaim' => "val1",
                'intClaim' => 56789,
                'myprefix_testClaim2' => "val2",
                'myprefix_boolClaim' => true,
            ]
        );
    }
}
