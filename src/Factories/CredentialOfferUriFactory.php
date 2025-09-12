<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use DateTimeImmutable;
use RuntimeException;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\ParametersEnum;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\IssuerStateEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\VerifiableCredentials;
use SimpleSAML\OpenID\VerifiableCredentials\TxCode;

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
        protected readonly EmailFactory $emailFactory,
        protected readonly IssuerStateEntityFactory $issuerStateEntityFactory,
        protected readonly IssuerStateRepository $issuerStateRepository,
    ) {
    }

    /**
     * @param string[] $credentialConfigurationIds
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    public function buildForAuthorization(
        array $credentialConfigurationIds,
    ): string {

        $issuerStateGenerationAttempts = 3;
        while ($issuerStateGenerationAttempts-- > 0) {
            try {
                $issuerState = $this->issuerStateEntityFactory->buildNew();
                $this->issuerStateRepository->persist($issuerState);
                break;
            } catch (\Throwable $e) {
                if ($issuerStateGenerationAttempts === 0) {
                    $this->loggerService->error(
                        'All attempts to generate Issuer State failed: ' . $e->getMessage(),
                    );
                    throw new OpenIdException('Failed to generate issuer state.', previous: $e);
                }

                $this->loggerService->warning('Failed to generate Issuer State: ' . $e->getMessage());
            }
        }

        /** @psalm-var \SimpleSAML\Module\oidc\Entities\IssuerStateEntity $issuerState */

        $credentialOffer = $this->verifiableCredentials->credentialOfferFactory()->from(
            parameters: [
                ClaimsEnum::CredentialIssuer->value => $this->moduleConfig->getIssuer(),
                ClaimsEnum::CredentialConfigurationIds->value => [
                    ...$credentialConfigurationIds,
                ],
                ClaimsEnum::Grants->value => [
                    GrantTypesEnum::AuthorizationCode->value => [
                        ClaimsEnum::IssuerState->value => $issuerState->getValue(),
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

    /**
     * @param string[] $credentialConfigurationIds
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    public function buildPreAuthorized(
        array $credentialConfigurationIds,
        array $userAttributes,
        bool $useTxCode = false,
        string $userEmailAttributeName = null,
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

        // TODO mivanci Wallet (client) credential_offer_endpoint metadata
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#client-metadata

        $scopes = array_map(
            fn (string $scope) => new ScopeEntity($scope),
            ['openid', ...$credentialConfigurationIds],
        );

        // Currently, we need a dedicated client for which the PreAuthZed code will be bound to.
        // TODO mivanci: Remove requirement for dedicated client for (pre-)authorization codes.
        $client = $this->clientEntityFactory->getGenericForVci();
        if ($this->clientRepository->findById($client->getIdentifier()) === null) {
            $this->clientRepository->add($client);
        } else {
            $this->clientRepository->update($client);
        }

        $userId = null;
        try {
            /** @psalm-suppress MixedAssignment */
            $userId = $this->sspBridge->utils()->attributes()->getExpectedAttribute(
                $userAttributes,
                $this->moduleConfig->getUserIdentifierAttribute(),
            );

            if (!is_scalar($userId)) {
                throw new RuntimeException('User identifier attribute value is not a string.');
            }
            $userId = strval($userId);
        } catch (\Throwable $e) {
            $this->loggerService->warning(
                'Could not extract user identifier from user attributes: ' . $e->getMessage(),
                $userAttributes,
            );
        }

        if ($userId === null) {
            $this->loggerService->warning('Falling back to user attributes hash for user identifier.');
            $sortedAttributes = $userAttributes;
            $this->verifiableCredentials->helpers()->arr()->hybridSort($sortedAttributes);
            $userId = 'vci_credential_offer_preauthz_' . hash('sha256', serialize($sortedAttributes));
            $this->loggerService->info(
                'Generated user identifier based on user attributes: ' . $userId,
                $userAttributes,
            );
        }

        $oldUserEntity = $this->userRepository->getUserEntityByIdentifier($userId);

        $userEntity = $this->userEntityFactory->fromData($userId, $userAttributes);

        if ($oldUserEntity instanceof UserEntity) {
            $this->userRepository->update($userEntity);
        } else {
            $this->userRepository->add($userEntity);
        }

        $txCode = null;
        $userEmail = null;
        $userEmailAttributeName ??= $this->moduleConfig->getDefaultUsersEmailAttributeName();
        if ($useTxCode) {
            $userEmail = $this->getUserEmail($userEmailAttributeName, $userAttributes);
            $txCodeDescription = 'Please provide the one-time code that was sent to e-mail ' . $userEmail;
            $txCode = $this->buildTxCode($txCodeDescription);
            $this->loggerService->debug(
                'Generated TxCode for sending by email: ' . $txCode->getCodeAsString(),
                $txCode->jsonSerialize(),
            );
        }

        $authCodeIdGenerationAttempts = 3;
        while ($authCodeIdGenerationAttempts-- > 0) {
            try {
                $authCode = $this->authCodeEntityFactory->fromData(
                    id: $this->sspBridge->utils()->random()->generateID(),
                    client: $client,
                    scopes: $scopes,
                    expiryDateTime: (new DateTimeImmutable())->add($this->moduleConfig->getAuthCodeDuration()),
                    userIdentifier: $userId,
                    redirectUri: 'openid-credential-offer://',
                    isPreAuthorized: true,
                    txCode: $txCode instanceof VerifiableCredentials\TxCode ? $txCode->getCodeAsString() : null,
                );
                $this->authCodeRepository->persistNewAuthCode($authCode);
                break;
            } catch (\Throwable $e) {
                if ($authCodeIdGenerationAttempts === 0) {
                    $this->loggerService->error(
                        'All attempts to generate Authorization Code failed: ' . $e->getMessage(),
                    );
                    throw new OpenIdException('Failed to generate Authorization Code.', previous: $e);
                }

                $this->loggerService->warning('Failed to generate Authorization Code ID: ' . $e->getMessage());
            }
        }

        /** @psalm-var \SimpleSAML\Module\oidc\Entities\AuthCodeEntity $authCode */

        $credentialOffer = $this->verifiableCredentials->credentialOfferFactory()->from(
            parameters: [
                ClaimsEnum::CredentialIssuer->value => $this->moduleConfig->getIssuer(),
                ClaimsEnum::CredentialConfigurationIds->value => [
                    ...$credentialConfigurationIds,
                ],
                ClaimsEnum::Grants->value => [
                    GrantTypesEnum::PreAuthorizedCode->value => [
                        ClaimsEnum::PreAuthorizedCode->value => $authCode->getIdentifier(),
                        ...(array_filter(
                            [
                                ClaimsEnum::TxCode->value => $txCode instanceof VerifiableCredentials\TxCode ?
                                    $txCode->jsonSerialize() :
                                    null,
                            ],
                        )),
                    ],
                ],
            ],
        );

        if ($txCode instanceof VerifiableCredentials\TxCode && $userEmail !== null) {
            $this->sendTxCodeByEmail($txCode, $userEmail);
        }

        $credentialOfferValue = $credentialOffer->jsonSerialize();
        $parameterName = ParametersEnum::CredentialOfferUri->value;
        if (is_array($credentialOfferValue)) {
            $parameterName = ParametersEnum::CredentialOffer->value;
            $credentialOfferValue = json_encode($credentialOfferValue);
        }

        return "openid-credential-offer://?$parameterName=$credentialOfferValue";
    }

    /**
     * @param mixed[] $userAttributes
     * @throws RuntimeException
     */
    public function getUserEmail(string $userEmailAttributeName, array $userAttributes): string
    {
        try {
            $userEmail = $this->sspBridge->utils()->attributes()->getExpectedAttribute(
                $userAttributes,
                $userEmailAttributeName,
                true,
            );
        } catch (Exception $e) {
            throw new RuntimeException('Could not extract user email from user attributes: ' . $e->getMessage());
        }

        if (!is_string($userEmail)) {
            throw new RuntimeException('User email attribute value is not a string.');
        }

        return $userEmail;
    }

    public function buildTxCode(
        string $description,
        int|string $txCode = null,
    ): TxCode {
        $txCode ??= rand(1000, 9999);

        return $this->verifiableCredentials->txCodeFactory()->build(
            $txCode,
            $description,
        );
    }

    public function sendTxCodeByEmail(TxCode $txCode, string $email, string $subject = null): void
    {
        $subject ??= 'Your one-time code';

        $email = $this->emailFactory->build(
            subject: $subject,
            to: $email,
        );

        $email->setText('Use the following code to complete the transaction.');

        $email->setData([
            'Transaction Code' => $txCode->getCodeAsString(),
        ]);

        $email->send();
    }
}
