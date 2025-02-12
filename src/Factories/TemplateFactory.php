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

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Configuration;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Admin\Menu;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\XHTML\Template;

class TemplateFactory
{
    protected bool $showMenu = true;
    protected bool $includeDefaultMenuItems = true;
    protected bool $showModuleName = true;
    protected bool $showSubPageTitle = true;

    public function __construct(
        protected readonly Configuration $sspConfiguration,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Menu $oidcMenu,
        protected readonly SspBridge $sspBridge,
        protected readonly SessionMessagesService $sessionMessagesService,
        protected readonly Routes $routes,
    ) {
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function build(
        string $templateName,
        array $data = [],
        ?string $activeHrefPath = null,
        ?bool $includeDefaultMenuItems = null,
        ?bool $showMenu = null,
        ?bool $showModuleName = null,
        ?bool $showSubPageTitle = null,
    ): Template {
        $template = new Template($this->sspConfiguration, $templateName);

        $includeDefaultMenuItems ??= $this->includeDefaultMenuItems;
        $showMenu ??= $this->showMenu;
        $showModuleName ??= $this->showModuleName;
        $showSubPageTitle ??= $this->showSubPageTitle;

        if ($includeDefaultMenuItems) {
            $this->includeDefaultMenuItems();
        }

        if ($activeHrefPath) {
            $this->setActiveHrefPath($activeHrefPath);
        }

        $template->data = [
            'sspConfiguration' => $this->sspConfiguration,
            'moduleConfiguration' => $this->moduleConfig,
            'oidcMenu' => $this->oidcMenu,
            'showMenu' => $showMenu,
            'showModuleName' => $showModuleName,
            'showSubpageTitle' => $showSubPageTitle,
            'sessionMessages' => $this->sessionMessagesService->getMessages(),
            'routes' => $this->routes,
        ];

        if ($this->showMenu && $this->sspBridge->module()->isModuleEnabled('admin')) {
            $template->addTemplatesFromModule('admin');
            $sspMenu = $this->sspBridge->module()->admin()->buildSspAdminMenu();
            $sspMenu->addOption(
                'logout',
                $this->sspBridge->utils()->auth()->getAdminLogoutURL(),
                Translate::noop('Log out'),
            );
            $template = $sspMenu->insert($template);
            $template->data['frontpage_section'] = ModuleConfig::MODULE_NAME;
        }

        $template->data += $data;

        return $template;
    }

    protected function includeDefaultMenuItems(): void
    {
        $this->oidcMenu->addItem(
            $this->oidcMenu->buildItem(
                $this->moduleConfig->getModuleUrl(RoutesEnum::AdminMigrations->value),
                Translate::noop('Database Migrations'),
            ),
        );

        $this->oidcMenu->addItem(
            $this->oidcMenu->buildItem(
                $this->moduleConfig->getModuleUrl(RoutesEnum::AdminClients->value),
                Translate::noop('Client Registry'),
            ),
        );

        $this->oidcMenu->addItem(
            $this->oidcMenu->buildItem(
                $this->moduleConfig->getModuleUrl(RoutesEnum::AdminConfigProtocol->value),
                Translate::noop('Protocol Settings'),
            ),
        );

        $this->oidcMenu->addItem(
            $this->oidcMenu->buildItem(
                $this->moduleConfig->getModuleUrl(RoutesEnum::AdminConfigFederation->value),
                Translate::noop('Federation Settings'),
            ),
        );

        $this->oidcMenu->addItem(
            $this->oidcMenu->buildItem(
                $this->moduleConfig->getModuleUrl(RoutesEnum::AdminTestTrustChainResolution->value),
                Translate::noop('Test Trust Chain Resolution'),
            ),
        );

        $this->oidcMenu->addItem(
            $this->oidcMenu->buildItem(
                $this->moduleConfig->getModuleUrl(RoutesEnum::AdminTestTrustMarkValidation->value),
                Translate::noop('Test Trust Mark Validation'),
            ),
        );
    }

    public function setShowMenu(bool $showMenu): TemplateFactory
    {
        $this->showMenu = $showMenu;
        return $this;
    }

    public function setIncludeDefaultMenuItems(bool $includeDefaultMenuItems): TemplateFactory
    {
        $this->includeDefaultMenuItems = $includeDefaultMenuItems;
        return $this;
    }

    public function setActiveHrefPath(?string $activeHrefPath): TemplateFactory
    {
        $this->oidcMenu->setActiveHrefPath(
            $activeHrefPath ? $this->moduleConfig->getModuleUrl($activeHrefPath) : null,
        );
        return $this;
    }

    public function getActiveHrefPath(): ?string
    {
        return $this->oidcMenu->getActiveHrefPath();
    }

    public function setShowModuleName(bool $showModuleName): ?TemplateFactory
    {
        $this->showModuleName = $showModuleName;
        return $this;
    }

    public function setShowSubPageTitle(bool $showSubPageTitle): TemplateFactory
    {
        $this->showSubPageTitle = $showSubPageTitle;
        return $this;
    }
}
