<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Services;

use JsonException;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

/**
 * Class DatabaseLegacyOAuth2Import.
 */
class DatabaseLegacyOAuth2Import
{
    public function __construct(private readonly ClientRepository $clientRepository)
    {
    }

    /**
     * @psalm-suppress UndefinedClass, MixedAssignment, MixedArrayAccess, MixedArgument
     * @throws OidcServerException|JsonException
     */
    public function import(): void
    {
        if (!class_exists('\SimpleSAML\Modules\OAuth2\Repositories\ClientRepository')) {
            return;
        }

        $oauth2ClientRepository = new \SimpleSAML\Modules\OAuth2\Repositories\ClientRepository();
        $clients = $oauth2ClientRepository->findAll();

        foreach ($clients as $client) {
            if ($this->clientRepository->findById($client['id'])) {
                continue;
            }

            $this->clientRepository->add(ClientEntity::fromData(
                $client['id'],
                $client['secret'],
                $client['name'],
                $client['description'],
                $client['redirect_uri'],
                $client['scopes'],
                true,
                false,
                $client['auth_source']
            ));
        }
    }
}
