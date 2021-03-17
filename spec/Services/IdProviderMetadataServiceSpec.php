<?php

namespace spec\SimpleSAML\Modules\OpenIDConnect\Services;

use PhpSpec\ObjectBehavior;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Modules\OpenIDConnect\Services\IdProviderMetadataService;

class IdProviderMetadataServiceSpec extends ObjectBehavior
{
    public const IDP_HOSTED_METADATA = [
        'host' => '__DEFAULT__',
        'privatekey' => 'idp.example.org.pem',
        'certificate' => 'idp.example.org.crt',
        'auth' => 'example-userpass',
        'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'authproc' => [
            100 => [
                'class' => 'core:AttributeMap',
                0 => 'name2oid',
            ],
        ],
        'entityid' => 'https://idp.example.org/saml2/idp/metadata.php',
        'metadata-index' => 'https://idp.example.org/saml2/idp/metadata.php',
        'metadata-set' => 'saml20-idp-hosted',
    ];

    public function let(
        MetaDataStorageHandler $metaDataStorageHandler
    ): void {
        $this->beConstructedWith($metaDataStorageHandler);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(IdProviderMetadataService::class);
    }

    public function it_returns_expected_metadata(
        MetaDataStorageHandler $metaDataStorageHandler
    ): void {
        $metaDataStorageHandler->getMetaDataCurrent('saml20-idp-hosted')
            ->shouldBeCalled()
            ->willReturn(self::IDP_HOSTED_METADATA);

        $this->getMetadata()->shouldBe(self::IDP_HOSTED_METADATA);
    }
}
