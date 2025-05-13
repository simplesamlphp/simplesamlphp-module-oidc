<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum ParametersEnum: string
{
    case ClientId = 'client_id';
    case CredentialOffer = 'credential_offer';
    case CredentialOfferUri = 'credential_offer_uri';
}
