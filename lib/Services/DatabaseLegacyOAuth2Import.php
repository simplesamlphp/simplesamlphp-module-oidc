<?php

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

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use SimpleSAML\Modules\OAuth2;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;

class DatabaseLegacyOAuth2Import
{
    /**
     * @var \SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository
     */
    private $clientRepository;


    /**
     * @param \SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository $clientRepository
     */
    public function __construct(ClientRepository $clientRepository)
    {
        $this->clientRepository = $clientRepository;
    }


    /**
     * @return void
     */
    public function import()
    {
        if (!class_exists('\SimpleSAML\Modules\OAuth2\Repositories\ClientRepository')) {
            return;
        }

        $oauth2ClientRepository = new OAuth2\Repositories\ClientRepository();
        $clients = $oauth2ClientRepository->findAll();

        /** @var \OAuth2\Entity\ClientEntity $client */
        foreach ($clients as $client) {
            if ($this->clientRepository->findById($client['id'])) {
                continue;
            }

            $this->clientRepository->add(ClientEntity::fromData(
                $client['id'],
                $client['secret'],
                $client['name'],
                $client['description'],
                $client['auth_source'],
                $client['redirect_uri'],
                $client['scopes'],
                true
            ));
        }
    }
}
