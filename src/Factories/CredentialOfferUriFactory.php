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
        protected readonly ClientRepository $clientRepository,
        protected readonly LoggerService $loggerService,
        protected readonly UserRepository $userRepository,
        protected readonly UserEntityFactory $userEntityFactory,
        protected readonly EmailFactory $emailFactory,
        protected readonly IssuerStateEntityFactory $issuerStateEntityFactory,
        protected readonly IssuerStateRepository $issuerStateRepository,
        protected readonly UserIdentifierResolver $userIdentifierResolver,
    ) {
    }

    /**
     * @param string[] $credentialConfigurationIds
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \JsonException
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

        return $this->buildUri($credentialOffer->jsonSerialize());
    }

    /**
     * @param string[] $credentialConfigurationIds
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \JsonException
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

        $credentialConfigurationIdsSupported = $this->moduleConfig->getVciCredentialConfigurationIdsSupported();

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
        // TODO mivanci: Remove requirement for dedicated client for (pre-)authorization codes once the dynamic
        // client registration is enabled.
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
        } catch (\Throwable) {
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
        $userEmail = null;
        $userEmailAttributeName ??= $this->moduleConfig->getDefaultUsersEmailAttributeName();
        if ($useTxCode) {
            $userEmail = $this->getUserEmail($userEmailAttributeName, $userAttributes);
            $txCodeDescription = 'Please provide the one-time code that was sent to e-mail ' . $userEmail;
            $txCode = $this->buildTxCode($txCodeDescription);
            $this->loggerService->debug('Generated transaction code for delivery by email.');
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

        return $this->buildUri($credentialOffer->jsonSerialize());
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
