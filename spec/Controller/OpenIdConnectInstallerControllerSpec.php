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

namespace spec\SimpleSAML\Modules\OpenIDConnect\Controller;

use PhpSpec\ObjectBehavior;
use SimpleSAML\Modules\OpenIDConnect\Controller\OpenIdConnectInstallerController;
use SimpleSAML\Modules\OpenIDConnect\Factories\TemplateFactory;
use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseLegacyOAuth2Import;
use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration;
use SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService;
use SimpleSAML\XHTML\Template;
use Zend\Diactoros\Response\RedirectResponse;
use Zend\Diactoros\ServerRequest;

class OpenIdConnectInstallerControllerSpec extends ObjectBehavior
{
    /**
     * @return void
     */
    public function let(
        TemplateFactory $templateFactory,
        SessionMessagesService $messages,
        DatabaseMigration $databaseMigration,
        DatabaseLegacyOAuth2Import $databaseLegacyOAuth2Import
    ) {
        $databaseMigration->isUpdated()->willReturn(false);

        $this->beConstructedWith(
            $templateFactory,
            $messages,
            $databaseMigration,
            $databaseLegacyOAuth2Import
        );
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(OpenIdConnectInstallerController::class);
    }

    /**
     * @return void
     */
    public function it_returns_to_main_page_if_already_updated(
        DatabaseMigration $databaseMigration,
        ServerRequest $request
    ) {
        $databaseMigration->isUpdated()->shouldBeCalled()->willReturn(true);

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }

    /**
     * @return void
     */
    public function it_shows_information_page(
        ServerRequest $request,
        TemplateFactory $templateFactory,
        Template $template
    ) {
        $request->getParsedBody()->shouldBeCalled();
        $request->getMethod()->shouldBeCalled()->willReturn('GET');

        $templateFactory->render('oidc:install.twig', [
            'oauth2_enabled' => false,
        ])->shouldBeCalled()->willReturn($template);

        $this->__invoke($request)->shouldBeLike($template);
    }

    /**
     * @param \SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService $messages
     *
     * @return void
     */
    public function it_requires_confirmation_before_install_schema(
        DatabaseMigration $databaseMigration,
        ServerRequest $request,
        TemplateFactory $templateFactory,
        Template $template
    ) {
        $request->getParsedBody()->shouldBeCalled();
        $request->getMethod()->shouldBeCalled()->willReturn('POST');
        $databaseMigration->migrate()->shouldNotBeCalled();

        $templateFactory->render('oidc:install.twig', [
            'oauth2_enabled' => false,
        ])->shouldBeCalled()->willReturn($template);

        $this->__invoke($request)->shouldBeLike($template);
    }

    /**
     * @return void
     */
    public function it_creates_schema(
        DatabaseMigration $databaseMigration,
        DatabaseLegacyOAuth2Import $databaseLegacyOAuth2Import,
        ServerRequest $request,
        SessionMessagesService $messages
    ) {
        $request->getParsedBody()->shouldBeCalled()->willReturn([
            'migrate' => true,
        ]);
        $request->getMethod()->shouldBeCalled()->willReturn('POST');

        $databaseMigration->migrate()->shouldBeCalled();
        $databaseLegacyOAuth2Import->import()->shouldNotBeCalled();
        $messages->addMessage('{oidc:install:finished}')->shouldBeCalled();

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }

    /**
     * @return void
     */
    public function it_imports_data_from_oauth2_module(
        DatabaseMigration $databaseMigration,
        DatabaseLegacyOAuth2Import $databaseLegacyOAuth2Import,
        ServerRequest $request,
        SessionMessagesService $messages
    ) {
        $request->getParsedBody()->shouldBeCalled()->willReturn([
            'migrate' => true,
            'oauth2_migrate' => true,
        ]);
        $request->getMethod()->shouldBeCalled()->willReturn('POST');

        $databaseMigration->migrate()->shouldBeCalled();
        $databaseLegacyOAuth2Import->import()->shouldBeCalled();
        $messages->addMessage('{oidc:install:finished}')->shouldBeCalled();
        $messages->addMessage('{oidc:import:finished}')->shouldBeCalled();

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }
}
