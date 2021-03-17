<?php

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use SimpleSAML\Metadata\MetaDataStorageHandler;

/**
 * Serves SAML IdP Metadata.
 *
 * Class IdProviderMetadataService
 * @package SimpleSAML\Modules\OpenIDConnect\Services
 */
class IdProviderMetadataService
{
    /**
     * @var MetaDataStorageHandler $metaDataStorageHandler
     */
    private $metaDataStorageHandler;

    public function __construct(MetaDataStorageHandler $metaDataStorageHandler)
    {
        $this->metaDataStorageHandler = $metaDataStorageHandler;
    }

    /**
     * Get current IdP metadata.
     *
     * @return array
     */
    public function getMetadata(): array
    {
        return $this->metaDataStorageHandler->getMetaDataCurrent('saml20-idp-hosted');
    }
}
