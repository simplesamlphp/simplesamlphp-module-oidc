<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Admin;

use SimpleSAML\Auth\Simple;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Factories\CredentialOfferUriFactory;
use SimpleSAML\Module\oidc\Factories\EmailFactory;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\VerifiableCredentials;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class VerifiableCredentailsTestController
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly TemplateFactory $templateFactory,
        protected readonly Authorization $authorization,
        protected readonly LoggerService $loggerService,
        protected readonly EmailFactory $emailFactory,
        protected readonly AuthSimpleFactory $authSimpleFactory,
        protected readonly SessionService $sessionService,
        protected readonly SspBridge $sspBridge,
        protected readonly Routes $routes,
        protected readonly CredentialOfferUriFactory $credentialOfferUriFactory,
    ) {
        $this->authorization->requireAdmin(true);
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     */
    public function verifiableCredentialIssuance(Request $request): Response
    {
        $setupErrors = [];

        if (!$this->moduleConfig->getVerifiableCredentialEnabled()) {
            $setupErrors[] = 'Verifiable Credential functionalities are not enabled.';
        }

        $selectedAuthSourceId = $this->sessionService->getCurrentSession()->getData('vci', 'auth_source_id');

        $authSource = null;
        if (is_string($selectedAuthSourceId)) {
            $authSource = $this->authSimpleFactory->forAuthSourceId($selectedAuthSourceId);
        }

        // Check if the logout was called.
        if (
            $request->request->has('logout') &&
            $authSource instanceof Simple &&
            $authSource->isAuthenticated()
        ) {
            $this->sessionService->getCurrentSession()->deleteData('vci', 'auth_source_id');
            $selectedAuthSourceId = null;
            $authSource->logout();
        } elseif (is_string($newAuthSourceId = $request->get('authSourceId'))) {
            $authSource = $this->authSimpleFactory->forAuthSourceId($newAuthSourceId);
            $this->sessionService->getCurrentSession()->setData('vci', 'auth_source_id', $newAuthSourceId);
            $selectedAuthSourceId = $newAuthSourceId;
        }

        $authSourceIds = array_filter(
            $this->sspBridge->auth()->source()->getSources(),
            fn (string $authSourceId): bool => $authSourceId !== 'admin',
        );

        if (
            $authSource instanceof Simple &&
            ($authSource->isAuthenticated() === false) &&
            is_string($selectedAuthSourceId) &&
            in_array($selectedAuthSourceId, $authSourceIds, true)
        ) {
            $authSource->login(['ReturnTo' => $this->routes->urlAdminTestVerifiableCredentialIssuance()]);
        }

        $selectedCredentialConfigurationId = $this->sessionService->getCurrentSession()->getData(
            'vci',
            'credential_configuration_id',
        );

        if (is_string($newCredentialConfigurationId = $request->get('credentialConfigurationId'))) {
            $this->sessionService->getCurrentSession()->setData(
                'vci',
                'credential_configuration_id',
                $newCredentialConfigurationId,
            );
            $selectedCredentialConfigurationId = $newCredentialConfigurationId;
        }

        $credentialConfigurationIdsSupported = $this->moduleConfig->getCredentialConfigurationIdsSupported();

        if (empty($credentialConfigurationIdsSupported)) {
            $setupErrors[] = 'No credential configuration IDs configured.';
        }

        if (
            is_null($selectedCredentialConfigurationId) ||
            !in_array($selectedCredentialConfigurationId, $credentialConfigurationIdsSupported, true)
        ) {
            $selectedCredentialConfigurationId = current($credentialConfigurationIdsSupported);
        }

        $credentialOfferQrUri = null;
        $credentialOfferUri = null;

        if (
            $authSource instanceof Simple &&
            $authSource->isAuthenticated()
        ) {
            $userAttributes = $authSource->getAttributes();

            $credentialOfferUri = $this->credentialOfferUriFactory->buildPreAuthorized(
                [$selectedCredentialConfigurationId],
                $userAttributes,
            );

            // TODO mivanci Local QR code generator
            // https://quickchart.io/documentation/qr-codes/
            $credentialOfferQrUri = 'https://quickchart.io/qr?size=200&margin=1&text=' . urlencode($credentialOfferUri);
        }

        $authSourceActionRoute = $this->routes->urlAdminTestVerifiableCredentialIssuance();

        return $this->templateFactory->build(
            'oidc:tests/verifiable-credential-issuance.twig',
            compact(
                'setupErrors',
                'credentialOfferQrUri',
                'credentialOfferUri',
                'authSourceIds',
                'authSourceActionRoute',
                'authSource',
                'credentialConfigurationIdsSupported',
                'selectedCredentialConfigurationId',
            ),
            RoutesEnum::AdminTestVerifiableCredentialIssuance->value,
        );
    }
}
