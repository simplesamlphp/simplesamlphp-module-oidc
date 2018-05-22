<?php

namespace spec\SimpleSAML\Modules\OpenIDConnect\Controller;

use SimpleSAML\Modules\OpenIDConnect\Controller\OpenIdConnectInstallerController;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use SimpleSAML\Modules\OpenIDConnect\Factories\TemplateFactory;
use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseLegacyOAuth2Import;
use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration;
use SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService;
use Zend\Diactoros\Response\RedirectResponse;
use Zend\Diactoros\ServerRequest;

class OpenIdConnectInstallerControllerSpec extends ObjectBehavior
{
    function let(
        TemplateFactory $templateFactory,
        SessionMessagesService $messages,
        DatabaseMigration $databaseMigration,
        DatabaseLegacyOAuth2Import $databaseLegacyOAuth2Import
    )
    {
        $databaseMigration->isUpdated()->willReturn(false);

        $this->beConstructedWith(
            $templateFactory,
            $messages,
            $databaseMigration,
            $databaseLegacyOAuth2Import
        );
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(OpenIdConnectInstallerController::class);
    }

    function it_returns_to_main_page_if_already_updated(
        DatabaseMigration $databaseMigration,
        ServerRequest $request
    )
    {
        $databaseMigration->isUpdated()->shouldBeCalled()->willReturn(true);

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }
    
    function it_shows_information_page(
        ServerRequest $request,
        TemplateFactory $templateFactory,
        \SimpleSAML_XHTML_Template $template
    )
    {
        $request->getParsedBody()->shouldBeCalled();
        $request->getMethod()->shouldBeCalled()->willReturn('GET');
        
        $templateFactory->render('oidc:install.twig', [
            'oauth2_enabled' => false,
        ])->shouldBeCalled()->willReturn($template);

        $this->__invoke($request)->shouldBeLike($template);
    }

    function it_requires_confirmation_before_install_schema(
        DatabaseMigration $databaseMigration,
        ServerRequest $request,
        TemplateFactory $templateFactory,
        \SimpleSAML_XHTML_Template $template
    )
    {
        $request->getParsedBody()->shouldBeCalled();
        $request->getMethod()->shouldBeCalled()->willReturn('POST');
        $databaseMigration->migrate()->shouldNotBeCalled();

        $templateFactory->render('oidc:install.twig', [
            'oauth2_enabled' => false,
        ])->shouldBeCalled()->willReturn($template);

        $this->__invoke($request)->shouldBeLike($template);
    }

    function it_creates_schema(
        DatabaseMigration $databaseMigration,
        DatabaseLegacyOAuth2Import $databaseLegacyOAuth2Import,
        ServerRequest $request,
        SessionMessagesService $messages
    )
    {
        $request->getParsedBody()->shouldBeCalled()->willReturn([
            'migrate' => true,
        ]);
        $request->getMethod()->shouldBeCalled()->willReturn('POST');

        $databaseMigration->migrate()->shouldBeCalled();
        $databaseLegacyOAuth2Import->import()->shouldNotBeCalled();
        $messages->addMessage('{oidc:install:finished}')->shouldBeCalled();

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }

    function it_imports_data_from_oauth2_module(
        DatabaseMigration $databaseMigration,
        DatabaseLegacyOAuth2Import $databaseLegacyOAuth2Import,
        ServerRequest $request,
        SessionMessagesService $messages
    )
    {
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
