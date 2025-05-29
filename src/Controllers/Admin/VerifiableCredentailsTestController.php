<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Admin;

use SimpleSAML\Auth\Simple;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\ParametersEnum;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
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
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\VerifiableCredentials;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class VerifiableCredentailsTestController
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly TemplateFactory $templateFactory,
        protected readonly Authorization $authorization,
        protected readonly VerifiableCredentials $verifiableCredentials,
        protected readonly AuthCodeRepository $authCodeRepository,
        protected readonly AuthCodeEntityFactory $authCodeEntityFactory,
        protected readonly ClientRepository $clientRepository,
        protected readonly ClientEntityFactory $clientEntityFactory,
        protected readonly LoggerService $loggerService,
        protected readonly EmailFactory $emailFactory,
        protected readonly ?ProtocolCache $protocolCache,
        protected readonly SessionMessagesService $sessionMessagesService,
        protected readonly AuthSimpleFactory $authSimpleFactory,
        protected readonly SessionService $sessionService,
        protected readonly SspBridge $sspBridge,
        protected readonly Routes $routes,
        protected readonly UserRepository $userRepository,
        protected readonly UserEntityFactory $userEntityFactory,
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


        if (
            $authSource instanceof Simple &&
            ($authSource->isAuthenticated() === false) &&
            is_string($selectedAuthSourceId)
        ) {
            $authSource->login(['ReturnTo' => $this->routes->urlAdminTestVerifiableCredentialIssuance()]);
        }

        $authSourceIds = array_filter(
            $this->sspBridge->auth()->source()->getSources(),
            fn (string $authSourceId): bool => $authSourceId !== 'admin',
        );


        $credentialOfferQrUri = null;
        $credentialOfferUri = null;

        if (
            $authSource instanceof Simple &&
            $authSource->isAuthenticated()
        ) {
            $userAttributes = $authSource->getAttributes();

            $userId = $this->sspBridge->utils()->attributes()->getExpectedAttribute(
                $userAttributes,
                $this->moduleConfig->getUserIdentifierAttribute(),
            );

            // Persist / update user entity.
            $userEntity = $this->userRepository->getUserEntityByIdentifier($userId);

            if ($userEntity) {
                $userEntity->setClaims($userAttributes);
                $this->userRepository->update($userEntity);
            } else {
                $userEntity = $this->userEntityFactory->fromData($userId, $userAttributes);
                $this->userRepository->add($userEntity);
            }

            /* TODO mivanci TX Code handling
            $email = $this->emailFactory->build(
                subject: 'VC Issuance Transaction code',
                to: 'testuser@example.com',
            );

            $email->setData(['Transaction Code' => '1234']);
            try {
                $email->send();
                $this->sessionMessagesService->addMessage('Email with tx code sent to: testuser@example.com');
            } catch (Exception $e) {
                $this->sessionMessagesService->addMessage('Error emailing tx code.');
            }
            */

            // TODO mivanci Wallet (client) credential_offer_endpoint metadata
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#client-metadata

            // TODO mivanci Implement API and API clients hanlding, together with API client to OIDC client binding.
            $clientId = '1234567890';
            $clientSecret = '1234567890';

            if (($client = $this->clientRepository->findById($clientId)) === null) {
                $client = $this->clientEntityFactory->fromData(
                    id: $clientId,
                    secret: $clientSecret,
                    name: 'VCI Pre-authorized Code Test Client',
                    description: 'Test client for VCI Pre-authorized Code',
                    redirectUri: ['https://example.com/oidc/callback'],
                    scopes: ['openid', 'ResearchAndScholarshipCredentialJwtVcJson'], // TODO mivanci from config
                    isEnabled: true,
                );

                $this->clientRepository->add($client);
            }
            $authCodeId = '1234567890';

            // TODO mivanci Add indication of preauthz code to the auth code table.

            if (($authCode = $this->authCodeRepository->findById($authCodeId)) === null) {
                $authCode = $this->authCodeEntityFactory->fromData(
                    id: $authCodeId,
                    client: $client,
                    scopes: [
                        new ScopeEntity('openid'),
                        new ScopeEntity('ResearchAndScholarshipCredentialJwtVcJson'),
                    ],
                    expiryDateTime: new \DateTimeImmutable('+1 month'),
                    userIdentifier: $userId,
                    redirectUri: 'https://example.com/oidc/callback',
                    nonce: '1234567890',
                );

                $this->authCodeRepository->persistNewAuthCode($authCode);
            }

            $credentialOffer = $this->verifiableCredentials->credentialOfferFactory()->from(
                parameters: [
                    ClaimsEnum::CredentialIssuer->value => $this->moduleConfig->getIssuer(),
                    ClaimsEnum::CredentialConfigurationIds->value => [
                        'ResearchAndScholarshipCredentialJwtVcJson', // TODO mivanci from config
                    ],
                    ClaimsEnum::Grants->value => [
                        GrantTypesEnum::PreAuthorizedCode->value => [
                            ClaimsEnum::PreAuthorizedCode->value => $authCode->getIdentifier(),
                            // TODO mivanci support for TxCode
                            //                        ClaimsEnum::TxCode->value => [
                            //                            ClaimsEnum::InputMode->value => 'numeric',
                            //                            ClaimsEnum::Length->value => 6,
                            //                            ClaimsEnum::Description->value => 'Sent to user mail',
                            //                        ],
                        ],
                    ],
                ],
            );

            $credentialOfferValue = $credentialOffer->jsonSerialize();
            $parameterName = ParametersEnum::CredentialOfferUri->value;
            if (is_array($credentialOfferValue)) {
                $parameterName = ParametersEnum::CredentialOffer->value;
                $credentialOfferValue = json_encode($credentialOfferValue);
            }

            $credentialOfferUri = "openid-credential-offer://?$parameterName=$credentialOfferValue";

            // https://quickchart.io/documentation/qr-codes/
            $credentialOfferQrUri = 'https://quickchart.io/qr?size=200&margin=1&text=' . urlencode($credentialOfferUri);
        }





        $authSourceActionRoute = $this->routes->urlAdminTestVerifiableCredentialIssuance();

        return $this->templateFactory->build(
            'oidc:tests/verifiable-credential-issuance.twig',
            compact(
                'credentialOfferQrUri',
                'credentialOfferUri',
                'authSourceIds',
                'authSourceActionRoute',
                'authSource',
            ),
            RoutesEnum::AdminTestVerifiableCredentialIssuance->value,
        );
    }
}
