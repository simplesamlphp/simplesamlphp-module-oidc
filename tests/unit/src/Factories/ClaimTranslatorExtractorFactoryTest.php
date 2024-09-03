<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Factories;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Factories\ClaimTranslatorExtractorFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;

/**
 * @covers \SimpleSAML\Module\oidc\Factories\ClaimTranslatorExtractorFactory
 */
class ClaimTranslatorExtractorFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock
            ->method('config')
            ->willReturn(
                Configuration::loadFromArray(
                    [
                        ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE => 'uid',
                        ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE => [
                            'testClaim' => ['attribute'],
                            'intClaim' => [
                                'type' => 'int',
                                'intAttribute',
                            ],
                            'testClaim2' => ['attribute2'],
                            'boolClaim' => [
                                'type' => 'bool',
                                'attributes' => ['boolAttribute'],
                            ],
                        ],
                    ],
                ),
            );
        $this->moduleConfigMock
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
                ],
            );
    }

    protected function prepareMockedInstance(): ClaimTranslatorExtractorFactory
    {
        return new ClaimTranslatorExtractorFactory($this->moduleConfigMock);
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(
            ClaimTranslatorExtractorFactory::class,
            $this->prepareMockedInstance(),
        );
    }

    /**
     * @throws \Exception
     */
    public function testCanBuildClaimTranslatorExtractor(): void
    {
        $this->assertInstanceOf(
            ClaimTranslatorExtractor::class,
            $this->prepareMockedInstance()->build(),
        );
    }

    /**
     * @throws \Exception
     */
    public function testExtractor(): void
    {
        $claimTranslatorExtractor = $this->prepareMockedInstance()->build();

        $this->assertSame(
            $claimTranslatorExtractor->getClaimSet('customScope2')->getClaims(),
            ['myprefix_testClaim2', 'myprefix_boolClaim'],
        );

        $claimData = $claimTranslatorExtractor->extract(
            ['openid', 'email', 'profile', 'customScope1', 'customScope2'],
            [
                'cn' => ['Firsty Lasty'],
                'attribute' => ['val1'],
                'intAttribute' => ['56789'],
                'boolAttribute' => ['yes'],
                'attribute2' => ['val2'],
            ],
        );

        $this->assertSame(
            $claimData,
            [
                'name' => "Firsty Lasty",
                'testClaim' => "val1",
                'intClaim' => 56789,
                'myprefix_testClaim2' => "val2",
                'myprefix_boolClaim' => true,
            ],
        );
    }
}
