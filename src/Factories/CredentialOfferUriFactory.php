<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use DateTimeImmutable;
use RuntimeException;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\ParametersEnum;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\IssuerStateEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\UserIdentifierResolver;
use SimpleSAML\Module\oidc\VerifiableCredentials\TxCodeAttemptLimiter;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\VerifiableCredentials;
use SimpleSAML\OpenID\VerifiableCredentials\TxCode;
use Throwable;

class CredentialOfferUriFactory
{
    /**
     * Shown by the wallet next to the Transaction Code field (OpenID4VCI 1.0 section 4.1.1). It names the channel
     * the code went out on, not the user's address, which the offer would otherwise carry wherever it is shown.
     */
    public const string TX_CODE_DESCRIPTION = 'Please provide the one-time code that was sent to your e-mail address.';

    /**
     * The longest Transaction Code description section 4.1.1 allows, in characters.
     */
    public const int TX_CODE_DESCRIPTION_MAX_LENGTH = 300;


    public function __construct(
        protected readonly VerifiableCredentials $verifiableCredentials,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly SspBridge $sspBridge,
        protected readonly AuthCodeRepository $authCodeRepository,
        protected readonly AuthCodeEntityFactory $authCodeEntityFactory,
        protected readonly ClientRepository $clientRepository,
        protected readonly LoggerService $loggerService,
        protected readonly UserRepository $userRepository,
        protected readonly UserEntityFactory $userEntityFactory,
        protected readonly EmailFactory $emailFactory,
        protected readonly IssuerStateEntityFactory $issuerStateEntityFactory,
        protected readonly IssuerStateRepository $issuerStateRepository,
        protected readonly UserIdentifierResolver $userIdentifierResolver,
        protected readonly TxCodeAttemptLimiter $txCodeAttemptLimiter,
    ) {
    }


    /**
     * The issuer state records the offered configurations, which are then the only ones a request following
     * the offer may ask for (OfferedCredentialsRule).
     *
     * @param string[] $credentialConfigurationIds
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \JsonException
     * @throws \RuntimeException When the configurations named can not be offered.
     * @throws \SimpleSAML\Error\ConfigurationError When a configuration is malformed.
     */
    public function buildForAuthorization(
        array $credentialConfigurationIds,
    ): string {
        $credentialConfigurationIds = $this->offerableCredentialConfigurationIds($credentialConfigurationIds);

        $issuerStateGenerationAttempts = 3;
        while ($issuerStateGenerationAttempts-- > 0) {
            try {
                $issuerState = $this->issuerStateEntityFactory->buildNew(
                    credentialConfigurationIds: $credentialConfigurationIds,
                );
                $this->issuerStateRepository->persist($issuerState);
                break;
            } catch (Throwable $e) {
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
                ClaimsEnum::CredentialConfigurationIds->value => $credentialConfigurationIds,
                ClaimsEnum::Grants->value => [
                    GrantTypesEnum::AuthorizationCode->value => [
                        ClaimsEnum::IssuerState->value => $issuerState->getValue(),
                    ],
                ],
            ],
        );

        return $this->buildUri($credentialOffer->jsonSerialize());
    }


    /**
     * @param string[] $credentialConfigurationIds
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \JsonException
     * @throws \RuntimeException When the configurations named can not be offered.
     * @throws \SimpleSAML\Error\ConfigurationError When a configuration is malformed.
     */
    public function buildPreAuthorized(
        array $credentialConfigurationIds,
        array $userAttributes,
        bool $useTxCode = false,
        string $userEmailAttributeName = null,
    ): string {
        $credentialConfigurationIds = $this->offerableCredentialConfigurationIds($credentialConfigurationIds);

        // TODO mivanci Wallet (client) credential_offer_endpoint metadata
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#client-metadata

        $scopes = array_map(
            fn (string $scope) => new ScopeEntity($scope),
            ['openid', ...$credentialConfigurationIds],
        );

        // A code has to belong to a client, and no wallet is known when the offer is made, so the code is
        // created for the generic VCI client. That client only ends up on the access token when the wallet
        // redeeming the code is not a registered one: a registered wallet gets the token issued to itself
        // (see PreAuthCodeGrant).
        $client = $this->clientRepository->getGenericForVci();

        $userId = null;
        try {
            $userId = $this->userIdentifierResolver->resolve(
                $this->moduleConfig->getUserIdentifierAttributes(),
                $userAttributes,
            );

            if ($userId === null) {
                throw new RuntimeException('User identifier attribute value is not available.');
            }
        } catch (Throwable) {
            $this->loggerService->warning('Could not extract user identifier from credential-offer attributes.');
        }

        if ($userId === null) {
            $this->loggerService->warning('Falling back to user attributes hash for user identifier.');
            $sortedAttributes = $userAttributes;
            $this->verifiableCredentials->helpers()->arr()->hybridSort($sortedAttributes);
            $userId = 'vci_credential_offer_preauthz_' . hash('sha256', serialize($sortedAttributes));
            $this->loggerService->info('Generated user identifier based on credential-offer attributes.');
        }

        $oldUserEntity = $this->userRepository->getUserEntityByIdentifier($userId);

        $userEntity = $this->userEntityFactory->fromData($userId, $userAttributes);

        if ($oldUserEntity instanceof UserEntity) {
            $this->userRepository->update($userEntity);
        } else {
            $this->userRepository->add($userEntity);
        }

        $txCode = null;
        $userEmailAttributeName ??= $this->moduleConfig->getDefaultUsersEmailAttributeName();
        if ($useTxCode) {
            $userEmail = $this->getUserEmail($userEmailAttributeName, $userAttributes);
            $txCode = $this->buildTxCode(self::TX_CODE_DESCRIPTION);
            $this->loggerService->debug('Generated transaction code for delivery by email.');

            // Delivered before the code is stored, so that a delivery which fails leaves behind no code
            // waiting for a transaction code nobody received.
            $this->sendTxCodeByEmail($txCode, $userEmail);
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
                    flowTypeEnum: FlowTypeEnum::VciPreAuthorizedCode,
                    txCode: $txCode instanceof TxCode ? $txCode->getCodeAsString() : null,
                );
                $this->authCodeRepository->persistNewAuthCode($authCode);
                break;
            } catch (Throwable $e) {
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

        // The code's attempts at its Transaction Code, which the token endpoint spends (PreAuthCodeGrant).
        if ($txCode instanceof TxCode) {
            $this->txCodeAttemptLimiter->open($authCode->getIdentifier(), $authCode->getExpiryDateTime());
        }

        $credentialOffer = $this->verifiableCredentials->credentialOfferFactory()->from(
            parameters: [
                ClaimsEnum::CredentialIssuer->value => $this->moduleConfig->getIssuer(),
                ClaimsEnum::CredentialConfigurationIds->value => $credentialConfigurationIds,
                ClaimsEnum::Grants->value => [
                    GrantTypesEnum::PreAuthorizedCode->value => [
                        ClaimsEnum::PreAuthorizedCode->value => $authCode->getIdentifier(),
                        ...(array_filter(
                            [
                                ClaimsEnum::TxCode->value => $txCode instanceof TxCode ?
                                    $txCode->jsonSerialize() :
                                    null,
                            ],
                        )),
                    ],
                ],
            ],
        );

        return $this->buildUri($credentialOffer->jsonSerialize());
    }


    /**
     * The configurations an offer may name, checked before anything is stored or mailed for it: at least one,
     * none twice, each one this issuer has (OpenID4VCI 1.0 section 4.1.1, "A non-empty array of unique strings
     * that each identify one of the keys" of `credential_configurations_supported`), and no configuration
     * malformed. That last check covers every configuration, not only the ones offered, since the Credential
     * Issuer metadata a wallet reads to redeem the offer is not built while any of them is
     * (CredentialIssuerMetadataService::buildMetadata()).
     *
     * @param mixed[] $credentialConfigurationIds
     * @return list<string>
     * @throws \RuntimeException When the configurations named can not be offered.
     * @throws \SimpleSAML\Error\ConfigurationError When a configuration is malformed.
     */
    protected function offerableCredentialConfigurationIds(array $credentialConfigurationIds): array
    {
        if ($credentialConfigurationIds === []) {
            throw new RuntimeException('No credential configuration IDs provided.');
        }

        $credentialConfigurationIdsSupported = $this->moduleConfig->getVciCredentialConfigurationIdsSupported();

        if ($credentialConfigurationIdsSupported === []) {
            throw new RuntimeException('No credential configuration IDs configured.');
        }

        $offerableCredentialConfigurationIds = [];
        /** @psalm-suppress MixedAssignment */
        foreach ($credentialConfigurationIds as $credentialConfigurationId) {
            // Compared strictly, so neither a number (7) nor another spelling of a number ('7.0') is taken for an
            // id such as '7'.
            if (!in_array($credentialConfigurationId, $credentialConfigurationIdsSupported, true)) {
                throw new RuntimeException('Unsupported credential configuration IDs provided.');
            }

            if (in_array($credentialConfigurationId, $offerableCredentialConfigurationIds, true)) {
                throw new RuntimeException('Repeated credential configuration IDs provided.');
            }

            $offerableCredentialConfigurationIds[] = $credentialConfigurationId;
        }

        $this->moduleConfig->validateVciCredentialConfigurations();

        return $offerableCredentialConfigurationIds;
    }


    /**
     * Build the offer URI a wallet is sent to, carrying the offer either by value or by reference.
     *
     * The offer travels as a query parameter, so its value has to be percent encoded. A by-reference
     * offer is a URL which may carry a query string of its own, and a by-value offer is JSON, full of
     * characters a query cannot hold literally. Appended raw, an '&' in either would split the value
     * into a second parameter and a '#' would truncate it into a fragment.
     *
     * @param string|mixed[] $credentialOffer A URI to the offer, or the offer parameters themselves.
     * @throws \JsonException
     */
    protected function buildUri(string|array $credentialOffer): string
    {
        if (is_array($credentialOffer)) {
            $parameterName = ParametersEnum::CredentialOffer->value;
            $parameterValue = json_encode($credentialOffer, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } else {
            $parameterName = ParametersEnum::CredentialOfferUri->value;
            $parameterValue = $credentialOffer;
        }

        return 'openid-credential-offer://?' . http_build_query(
            [$parameterName => $parameterValue],
            encoding_type: PHP_QUERY_RFC3986,
        );
    }


    /**
     * @param mixed[] $userAttributes
     * @throws \RuntimeException
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


    /**
     * @throws \RuntimeException When the description is longer than OpenID4VCI 1.0 section 4.1.1 allows.
     */
    public function buildTxCode(
        string $description,
        int|string $txCode = null,
    ): TxCode {
        if (mb_strlen($description) > self::TX_CODE_DESCRIPTION_MAX_LENGTH) {
            throw new RuntimeException(sprintf(
                'Transaction Code description is longer than %d characters.',
                self::TX_CODE_DESCRIPTION_MAX_LENGTH,
            ));
        }

        $txCode ??= random_int(1000, 9999);

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
