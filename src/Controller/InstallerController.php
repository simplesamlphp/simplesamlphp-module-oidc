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
namespace SimpleSAML\Module\oidc\Controller;

use Exception;
use SimpleSAML\XHTML\Template;
use SimpleSAML\Module;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Services\DatabaseLegacyOAuth2Import;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Utils\HTTP;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;

use function in_array;

class InstallerController
{
    public function __construct(
        private readonly TemplateFactory $templateFactory,
        private readonly SessionMessagesService $messages,
        private readonly DatabaseMigration $databaseMigration,
        private readonly DatabaseLegacyOAuth2Import $databaseLegacyOAuth2Import,
    ) {
    }

    /**
     * @throws Exception
     */
    public function __invoke(ServerRequest $request): Template|RedirectResponse
    {
        if ($this->databaseMigration->isUpdated()) {
            return new RedirectResponse((new HTTP())->addURLParameters('admin-clients/index.php', []));
        }

        $oauth2Enabled = in_array('oauth2', Module::getModules(), true);

        $parsedBody = $request->getParsedBody();
        if ('POST' === $request->getMethod() && ($parsedBody['migrate'] ?? false)) {
            $this->databaseMigration->migrate();
            $this->messages->addMessage('{oidc:install:finished}');

            if ($parsedBody['oauth2_migrate'] ?? false) {
                $this->databaseLegacyOAuth2Import->import();
                $this->messages->addMessage('{oidc:import:finished}');
            }

            return new RedirectResponse((new HTTP())->addURLParameters('admin-clients/index.php', []));
        }

        return $this->templateFactory->render('oidc:install.twig', [
            'oauth2_enabled' => $oauth2Enabled,
        ]);
    }
}
