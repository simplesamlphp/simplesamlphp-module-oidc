<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Admin;

use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Codebooks\ParametersEnum;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\VerifiableCredentials;
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
    ) {
        $this->authorization->requireAdmin(true);
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     */
    public function verifiableCredentialIssuance(): Response
    {
        $sampleData = [
            'eduPersonPrincipalName' => 'testuser@example.com',
            'eduPersonTargetedID' => 'abc123',
            'displayName' => 'Test User',
            'givenName' => 'Test',
            'sn' => 'User',
            'mail' => 'testuser@example.com',
            'eduPersonScopedAffiliation' => 'member@example.com',
        ];

        $this->loggerService->info('test', $sampleData);

        // TODO mivanci Wallet (client) credential_offer_endpoint metadata
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#client-metadata

        $clientId = '1234567890';
        $clientSecret = '1234567890';

        if (($client = $this->clientRepository->findById($clientId)) === null) {
            $client = $this->clientEntityFactory->fromData(
                id: $clientId,
                secret: $clientSecret,
                name: 'VCI Test Client',
                description: 'Test client for VCI',
                redirectUri: ['https://example.com/oidc/callback'],
                scopes: ['openid', 'ResearchAndScholarshipCredentialJwtVcJson'],
                isEnabled: true,
            );

            $this->clientRepository->add($client);
            ;
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
                userIdentifier: 'testuid',
                redirectUri: 'https://example.com/oidc/callback',
                nonce: '1234567890',
            );

            $this->authCodeRepository->persistNewAuthCode($authCode);
        }


        $credentialOffer = $this->verifiableCredentials->credentialOfferFactory()->from(
            parameters: [
                ClaimsEnum::CredentialIssuer->value => $this->moduleConfig->getIssuer(),
                ClaimsEnum::CredentialConfigurationIds->value => [
                    'ResearchAndScholarshipCredentialJwtVcJson',
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
        $qrUri = 'https://quickchart.io/qr?size=200&margin=1&text=' . urlencode($credentialOfferUri);

        return $this->templateFactory->build(
            'oidc:tests/verifiable-credential-issuance.twig',
            compact('qrUri', 'sampleData', 'credentialOfferUri'),
            RoutesEnum::AdminTestVerifiableCredentialIssuance->value,
        );
    }
}
