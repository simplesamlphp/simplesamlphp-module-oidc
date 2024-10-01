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

use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Modules\OAuth2\Repositories\ClientRepository as OAuth2ClientRepository;

/**
 * Class DatabaseLegacyOAuth2Import.
 */
class DatabaseLegacyOAuth2Import
{
    public function __construct(
        private readonly ClientRepository $clientRepository,
        private readonly ClientEntityFactory $clientEntityFactory,
    ) {
    }

    /**
     * @psalm-suppress UndefinedClass, MixedAssignment, MixedArrayAccess, MixedArgument
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function import(): void
    {
        if (!class_exists(ClientRepository::class)) {
            return;
        }

        $oauth2ClientRepository = new OAuth2ClientRepository();
        $clients = $oauth2ClientRepository->findAll();

        foreach ($clients as $client) {
            if ($this->clientRepository->findById($client['id'])) {
                continue;
            }

            $this->clientRepository->add($this->clientEntityFactory->fromData(
                $client['id'],
                $client['secret'],
                $client['name'],
                $client['description'],
                $client['redirect_uri'],
                $client['scopes'],
                true,
                false,
                $client['auth_source'],
            ));
        }
    }
}
