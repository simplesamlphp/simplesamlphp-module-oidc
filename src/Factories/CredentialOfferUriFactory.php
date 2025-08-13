<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use DateTimeImmutable;
use RuntimeException;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\ParametersEnum;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\VerifiableCredentials;

class CredentialOfferUriFactory
{
    public function __construct(
        protected readonly VerifiableCredentials $verifiableCredentials,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly SspBridge $sspBridge,
        protected readonly AuthCodeRepository $authCodeRepository,
        protected readonly AuthCodeEntityFactory $authCodeEntityFactory,
        protected readonly ClientEntityFactory $clientEntityFactory,
        protected readonly ClientRepository $clientRepository,
        protected readonly LoggerService $loggerService,
        protected readonly UserRepository $userRepository,
        protected readonly UserEntityFactory $userEntityFactory,
    ) {
    }

    /**
     * @param string[] $credentialConfigurationIds
     * @throws \SimpleSAML\OpenId\Exceptions\OpenIdException
     */
    public function buildPreAuthorized(
        array $credentialConfigurationIds,
        array $userAttributes,
    ): string {
        if (empty($credentialConfigurationIds)) {
            throw new RuntimeException('No credential configuration IDs provided.');
        }

        $credentialConfigurationIdsSupported = $this->moduleConfig->getCredentialConfigurationIdsSupported();

        if (empty($credentialConfigurationIdsSupported)) {
            throw new RuntimeException('No credential configuration IDs configured.');
        }

        if (array_diff($credentialConfigurationIds, $credentialConfigurationIdsSupported)) {
            throw new RuntimeException('Unsupported credential configuration IDs provided.');
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

        $scopes = array_map(
            fn (string $scope) => new ScopeEntity($scope),
            ['openid', ...$credentialConfigurationIds],
        );

        // Currently, we need a dedicated client for which the PreAuthZed code will be bound to.
        // TODO mivanci: Remove requirement for dedicated client for (pre-)authorization codes.
        $client = $this->clientEntityFactory->getGenericForVciPreAuthZFlow();
        if ($this->clientRepository->findById($client->getIdentifier()) === null) {
            $this->clientRepository->add($client);
        } else {
            $this->clientRepository->update($client);
        }

        $userId = null;
        try {
            $userId = $this->sspBridge->utils()->attributes()->getExpectedAttribute(
                $userAttributes,
                $this->moduleConfig->getUserIdentifierAttribute(),
            );
        } catch (\Throwable $e) {
            $this->loggerService->warning(
                'Could not extract user identifier from user attributes: ' . $e->getMessage(),
            );
        }

        if ($userId === null) {
            $sortedAttributes = $userAttributes;
            $this->verifiableCredentials->helpers()->arr()->hybridSort($sortedAttributes);
            $userId = 'vci_preauthz_' . hash('sha256', serialize($sortedAttributes));
        }

        $oldUserEntity = $this->userRepository->getUserEntityByIdentifier($userId);

        $userEntity = $this->userEntityFactory->fromData($userId, $userAttributes);

        if ($oldUserEntity instanceof UserEntity) {
            $this->userRepository->update($userEntity);
        } else {
            $this->userRepository->add($userEntity);
        }

        $authCodeId = null;
        $authCodeIdGenerationAttempts = 3;
        while ($authCodeIdGenerationAttempts > 0) {
            $authCodeId = $this->sspBridge->utils()->random()->generateID();
            if ($this->authCodeRepository->findById($authCodeId) === null) {
                break;
            }
            $authCodeIdGenerationAttempts--;
        }

        if ($authCodeId === null) {
            throw new RuntimeException('Failed to generate Authorization Code ID.');
        }

        // TODO mivanci Add indication of preAuthZ code to the auth code table.
        $authCode = $this->authCodeEntityFactory->fromData(
            id: $authCodeId,
            client: $client,
            scopes: $scopes,
            expiryDateTime: (new DateTimeImmutable())->add($this->moduleConfig->getAuthCodeDuration()),
            userIdentifier: $userId,
            redirectUri: 'openid-credential-offer://',
        );
        $this->authCodeRepository->persistNewAuthCode($authCode);

        $credentialOffer = $this->verifiableCredentials->credentialOfferFactory()->from(
            parameters: [
                ClaimsEnum::CredentialIssuer->value => $this->moduleConfig->getIssuer(),
                ClaimsEnum::CredentialConfigurationIds->value => [
                    ...$credentialConfigurationIds,
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

        return "openid-credential-offer://?$parameterName=$credentialOfferValue";
    }
}
