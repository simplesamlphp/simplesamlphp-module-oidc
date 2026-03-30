<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Admin;

use SimpleSAML\Auth\Simple;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Factories\CredentialOfferUriFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class VerifiableCredentailsTestController
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly TemplateFactory $templateFactory,
        protected readonly Authorization $authorization,
        protected readonly AuthSimpleFactory $authSimpleFactory,
        protected readonly SessionService $sessionService,
        protected readonly SspBridge $sspBridge,
        protected readonly Routes $routes,
        protected readonly CredentialOfferUriFactory $credentialOfferUriFactory,
        protected readonly RequestParamsResolver $requestParamsResolver,
    ) {
        $this->authorization->requireAdmin(true);
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @psalm-suppress MixedAssignment, InternalMethod
     */
    public function verifiableCredentialIssuance(Request $request): Response
    {
        if (!$this->moduleConfig->getVciEnabled()) {
            return $this->templateFactory->build(
                'oidc:tests/verifiable-credential-issuance.twig',
                ['setupErrors' => ['Verifiable Credential functionalities are not enabled.']],
                RoutesEnum::AdminTestVerifiableCredentialIssuance->value,
            );
        }

        $credentialConfigurationIdsSupported = $this->moduleConfig->getVciCredentialConfigurationIdsSupported();
        if (empty($credentialConfigurationIdsSupported)) {
            return $this->templateFactory->build(
                'oidc:tests/verifiable-credential-issuance.twig',
                ['setupErrors' => ['No credential configuration IDs configured.']],
                RoutesEnum::AdminTestVerifiableCredentialIssuance->value,
            );
        }

        $session = $this->sessionService->getCurrentSession();
        $allowedMethods = [HttpMethodsEnum::GET, HttpMethodsEnum::POST];

        if ($request->request->has('clear')) {
            $selectedAuthSourceId = $session->getData('vci', 'auth_source_id');
            if (is_string($selectedAuthSourceId)) {
                $authSource = $this->authSimpleFactory->forAuthSourceId($selectedAuthSourceId);
                if ($authSource->isAuthenticated()) {
                    $authSource->logout();
                }
            }
            $session->deleteData('vci', 'auth_source_id');
            $session->deleteData('vci', 'credential_configuration_id');

            return $this->routes->newRedirectResponseToModuleUrl(
                RoutesEnum::AdminTestVerifiableCredentialIssuance->value,
            );
        }

        $authSourceId = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            'authSourceId',
            $request,
            $allowedMethods,
        ) ?? $session->getData('vci', 'auth_source_id');

        $credentialConfigurationId = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            'credentialConfigurationId',
            $request,
            $allowedMethods,
        ) ?? $session->getData('vci', 'credential_configuration_id');

        $grantType = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            'grantType',
            $request,
            $allowedMethods,
        );

        $useTxCode = (bool) $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            'useTxCode',
            $request,
            $allowedMethods,
        );

        $usersEmailAttributeName = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            'usersEmailAttributeName',
            $request,
            $allowedMethods,
        );

        $authSourceIds = array_filter(
            $this->sspBridge->auth()->source()->getSources(),
            fn (string $id): bool => $id !== 'admin',
        );

        $authSource = is_string($authSourceId) ? $this->authSimpleFactory->forAuthSourceId($authSourceId) : null;

        if ($authSource instanceof Simple && $grantType === GrantTypesEnum::PreAuthorizedCode->value) {
            if (!$authSource->isAuthenticated()) {
                $session->setData('vci', 'auth_source_id', $authSourceId);
                $session->setData('vci', 'credential_configuration_id', $credentialConfigurationId);
                $authSource->login(['ReturnTo' => $this->routes->urlAdminTestVerifiableCredentialIssuance()]);
            }
        }

        $credentialOfferUri = null;
        if (is_string($credentialConfigurationId)) {
            if ($grantType === GrantTypesEnum::PreAuthorizedCode->value && $authSource?->isAuthenticated()) {
                $usersEmailAttributeName = is_string($usersEmailAttributeName) &&
                trim($usersEmailAttributeName) !== '' ?
                trim($usersEmailAttributeName) :
                $this->moduleConfig->getUsersEmailAttributeNameForAuthSourceId(
                    is_string($authSourceId) ? $authSourceId : '',
                );

                $credentialOfferUri = $this->credentialOfferUriFactory->buildPreAuthorized(
                    [$credentialConfigurationId],
                    $authSource->getAttributes(),
                    $useTxCode,
                    $usersEmailAttributeName,
                );
            } elseif ($grantType === GrantTypesEnum::AuthorizationCode->value) {
                $credentialOfferUri = $this->credentialOfferUriFactory->buildForAuthorization(
                    [$credentialConfigurationId],
                );
            }
        }

        $credentialOfferQrUri = is_string($credentialOfferUri)
        ? 'https://quickchart.io/qr?size=200&margin=1&text=' . urlencode($credentialOfferUri)
        : null;

        return $this->templateFactory->build(
            'oidc:tests/verifiable-credential-issuance.twig',
            [
                'setupErrors' => [],
                'credentialOfferQrUri' => $credentialOfferQrUri,
                'credentialOfferUri' => $credentialOfferUri,
                'authSourceIds' => $authSourceIds,
                'authSourceActionRoute' => $this->routes->urlAdminTestVerifiableCredentialIssuance(),
                'authSource' => $authSource,
                'credentialConfigurationIdsSupported' => $credentialConfigurationIdsSupported,
                'selectedCredentialConfigurationId' => $credentialConfigurationId,
                'defaultUsersEmailAttributeName' => $this->moduleConfig->getDefaultUsersEmailAttributeName(),
                'usersEmailAttributeName' => $usersEmailAttributeName,
                'grantTypesSupported' => [
                    GrantTypesEnum::PreAuthorizedCode->value => Translate::noop('Pre-authorized Code'),
                    GrantTypesEnum::AuthorizationCode->value => Translate::noop('Authorization Code'),
                ],
            ],
            RoutesEnum::AdminTestVerifiableCredentialIssuance->value,
        );
    }
}
