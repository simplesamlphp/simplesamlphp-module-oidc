<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Api;

use DateTimeImmutable;
use DateTimeZone;
use JsonException;
use RuntimeException;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Exceptions\InsufficientScopeException;
use SimpleSAML\Module\oidc\Exceptions\MissingTokenException;
use SimpleSAML\Module\oidc\Factories\CredentialOfferUriFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\CredentialOfferRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryPosition;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\ValueAbstracts\ApiCaller;
use SimpleSAML\Module\oidc\ValueAbstracts\CredentialConfigurationLimit;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\BuiltCredentialOffer;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\CredentialOfferRecord;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
use ValueError;

class VciCredentialOfferApiController
{
    final public const string HEADER_WWW_AUTHENTICATE = 'WWW-Authenticate';

    final public const string PARAM_CURSOR = 'cursor';

    /**
     * The credentials of an offer listed in one answer at most. An offer has no fixed size: its access token buys
     * credentials as often as its lifetime allows.
     */
    final public const int CREDENTIALS_PAGE_SIZE = 500;

    /**
     * The scopes which reach this endpoint: offering credentials, and asking what an offer produced.
     */
    protected const array SCOPES = [ApiScopesEnum::VciCredentialOffer, ApiScopesEnum::VciAll, ApiScopesEnum::All];

    /**
     * The only form an offer id is ever accepted in: 32 bytes as lower-case hex.
     */
    protected const string OFFER_ID_PATTERN = '/^[0-9a-f]{64}$/D';

    /**
     * The bounds of a cursor's components: a Status List entry's list id is a VARCHAR(64), which this module fills
     * with hex (a hash), so visible ASCII only, which keeps out a NUL byte PostgreSQL refuses to compare; its index is
     * an INT; and MySQL's DATETIME, the narrowest of the supported databases' moments, spans the years 1000 to 9999.
     * Moments are compared as strings in the stored format, which orders them as moments.
     */
    protected const string CURSOR_STATUS_LIST_ID_PATTERN = '/^[\x21-\x7E]{1,64}$/D';

    protected const int CURSOR_IDX_MAX = 2147483647;

    protected const string CURSOR_MOMENT_MIN = '1000-01-01 00:00:00';

    protected const string CURSOR_MOMENT_MAX = '9999-12-31 23:59:59';


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Authorization $authorization,
        protected readonly LoggerService $loggerService,
        protected readonly Routes $routes,
        protected readonly CredentialOfferUriFactory $credentialOfferUriFactory,
        protected readonly CredentialOfferRepository $credentialOfferRepository,
        protected readonly StatusListEntryRepository $statusListEntryRepository,
    ) {
        if (!$this->moduleConfig->getApiEnabled()) {
            $this->loggerService->warning('API capabilities not enabled.');
            throw OidcServerException::forbidden('API capabilities not enabled.');
        }

        if (!$this->moduleConfig->getVciEnabled()) {
            $this->loggerService->warning('Verifiable Credential capabilities not enabled.');
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled.');
        }
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function credentialOffer(Request $request): Response
    {
        if (!$this->moduleConfig->getApiVciCredentialOfferEndpointEnabled()) {
            $this->loggerService->warning('Credential Offer API endpoint not enabled.');
            throw OidcServerException::forbidden('Credential Offer API endpoint not enabled.');
        }

        $this->loggerService->debug('VciCredentialOfferApiController::credentialOffer');

        $this->loggerService->debug('VciCredentialOfferApiController: Processing credential-offer request.');

        try {
            // Null for an administrator's session, which owns no offer and may offer every configuration.
            $caller = $this->authorization->requireAdminOrTokenForAnyOfScope($request, self::SCOPES);
        } catch (AuthorizationException $e) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: AuthorizationException: ' . $e->getMessage(),
            );
            return $this->routes->newJsonErrorResponse(
                error: 'unauthorized',
                description: $e->getMessage(),
                httpCode: Response::HTTP_UNAUTHORIZED,
            );
        } catch (ConfigurationError $e) {
            // Who the token stands for, or its credential configurations, can not be read. That is this server's
            // configuration, not the caller's request, and the caller is answered in JSON as everywhere else in
            // this API.
            $this->loggerService->error(
                'VciCredentialOfferApiController: API token configuration could not be read: ' . $e->getMessage(),
            );
            return $this->routes->newJsonErrorResponse(
                error: 'server_error',
                description: 'Authorization could not be resolved.',
                httpCode: Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }

        $credentialConfigurationLimit = $caller?->getCredentialConfigurationLimit() ??
        CredentialConfigurationLimit::unlimited();
        $owner = $caller?->getPrincipal();

        $input = $request->getPayload()->all();

        $credentialConfigurationId = $input['credential_configuration_id'] ?? null;

        if (!is_string($credentialConfigurationId)) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: credential_configuration_id not provided or not a string.',
            );
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'No credential configuration ID (credential_configuration_id) provided.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        $credentialConfiguration = $this->moduleConfig->getVciCredentialConfiguration($credentialConfigurationId);

        if (!is_array($credentialConfiguration)) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: Provided Credential Configuration ID is not supported.',
                ['credentialConfigurationId' => $credentialConfigurationId],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'Provided credential configuration ID (credential_configuration_id) is not supported.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        // Checked after the configuration is known to exist, so an unknown one is answered as unknown whatever the
        // token's list says. Telling the caller that a configuration exists costs nothing: the Credential Issuer
        // metadata publishes every one. Both grants are held to the list: an authorization code offer carries no
        // attributes, but which credentials a token may advertise to wallets is still the token's limit.
        if (!$credentialConfigurationLimit->allows($credentialConfigurationId)) {
            $this->loggerService->warning(
                'VciCredentialOfferApiController: The API token may not offer this credential configuration.',
                ['credentialConfigurationId' => $credentialConfigurationId],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'insufficient_scope',
                description: 'The API token may not offer this credential configuration.',
                httpCode: Response::HTTP_FORBIDDEN,
                headers: [self::HEADER_WWW_AUTHENTICATE => 'Bearer error="insufficient_scope"'],
            );
        }

        $grantType = $input['grant_type'] ?? null;

        if (!is_string($grantType)) {
            $this->loggerService->error('VciCredentialOfferApiController: Grant Type (grant_type) not provided.');
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'No credential Grant Type (grant_type) provided.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        $grantTypeEnum = GrantTypesEnum::tryFrom($grantType);

        if (!$grantTypeEnum instanceof GrantTypesEnum) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: Invalid credential Grant Type (grant_type) provided.',
                ['grantType' => $grantType],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'Invalid credential Grant Type (grant_type) provided.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        if (!$grantTypeEnum->canBeUsedForVerifiableCredentialIssuance()) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: Provided Grant Type can not be used for verifiable credential' .
                ' issuance.',
                ['grantType' => $grantType],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'Provided Grant Type can not be used for verifiable credential issuance.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        $builtCredentialOffer = null;

        // Building an offer stores what it grants and may mail a transaction code. A failure there is this
        // server's (storage, mail delivery), and is answered as one in JSON, as every other answer of this API
        // is, rather than left to reach SimpleSAMLphp's HTML error page.
        try {
            if ($grantTypeEnum === GrantTypesEnum::AuthorizationCode) {
                $this->loggerService->debug(
                    'VciCredentialOfferApiController: AuthorizationCode Grant Type provided. Building credential ' .
                    'offer for Authorization Code Flow.',
                );
                $builtCredentialOffer = $this->credentialOfferUriFactory->buildForAuthorization(
                    [$credentialConfigurationId],
                    $owner,
                );
            }

            if ($grantTypeEnum === GrantTypesEnum::PreAuthorizedCode) {
                $this->loggerService->debug(
                    'VciCredentialOfferApiController: PreAuthorizedCode Grant Type provided. Building credential ' .
                    'offer for Pre-authorized Code Flow.',
                );

                /** @psalm-suppress MixedAssignment */
                $userAttributes = $input['user_attributes'] ?? [];
                $userAttributes = is_array($userAttributes) ? $userAttributes : [];
                $useTxCode = boolval($input['use_tx_code'] ?? false);
                /** @psalm-suppress MixedAssignment */
                $usersEmailAttributeName = $input['users_email_attribute_name'] ?? null;
                $usersEmailAttributeName = is_string($usersEmailAttributeName) ? $usersEmailAttributeName : null;
                /** @psalm-suppress MixedAssignment */
                $authenticationSourceId = $input['authentication_source_id'] ?? null;
                $authenticationSourceId = is_string($authenticationSourceId) ? $authenticationSourceId : null;

                if (is_null($usersEmailAttributeName) && is_string($authenticationSourceId)) {
                    $usersEmailAttributeName = $this->moduleConfig->getUsersEmailAttributeNameForAuthSourceId(
                        $authenticationSourceId,
                    );
                }

                $this->loggerService->debug(
                    'VciCredentialOfferApiController: Pre-authorized credential-offer request accepted.',
                    [
                        'useTxCode' => $useTxCode,
                        'authenticationSourceId' => $authenticationSourceId,
                        'usersEmailAttributeName' => $usersEmailAttributeName,
                    ],
                );

                // The transaction code goes to the user's email address, so attributes holding none are the
                // caller's mistake, answered as one before anything is stored.
                if ($useTxCode) {
                    try {
                        $this->credentialOfferUriFactory->getUserEmail(
                            $usersEmailAttributeName ?? $this->moduleConfig->getDefaultUsersEmailAttributeName(),
                            $userAttributes,
                        );
                    } catch (RuntimeException $exception) {
                        $this->loggerService->notice(
                            'VciCredentialOfferApiController: No email address for the transaction code: ' .
                            $exception->getMessage(),
                        );
                        return $this->routes->newJsonErrorResponse(
                            error: 'invalid_request',
                            description: 'User attributes hold no email address to send the transaction code to.',
                            httpCode: Response::HTTP_BAD_REQUEST,
                        );
                    }
                }

                $builtCredentialOffer = $this->credentialOfferUriFactory->buildPreAuthorized(
                    [$credentialConfigurationId],
                    $userAttributes,
                    $useTxCode,
                    $usersEmailAttributeName,
                    $owner,
                );
            }
        } catch (Throwable $exception) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: Credential Offer could not be built: ' . $exception->getMessage(),
                ['grantType' => $grantType],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'server_error',
                description: 'Credential Offer could not be built.',
                httpCode: Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }

        if ($builtCredentialOffer instanceof BuiltCredentialOffer) {
            // The offer id is what the caller keeps, to list later what the offer produced. It is neither the
            // pre-authorized code nor the issuer state, which redeem the offer.
            $data = [
                'credential_offer_uri' => $builtCredentialOffer->getUri(),
                'offer_id' => $builtCredentialOffer->getOfferId(),
            ];

            $this->loggerService->debug(
                'VciCredentialOfferApiController: Credential Offer URI built successfully.',
            );
            return $this->routes->newJsonResponse(
                data: $data,
            );
        }

        $this->loggerService->debug(
            'VciCredentialOfferApiController: Credential Offer URI NOT built for provided Grant Type.',
            ['grantType' => $grantType],
        );

        return $this->routes->newJsonErrorResponse(
            error: 'invalid_request',
            description: 'No implementation for provided Grant Type.',
            httpCode: Response::HTTP_BAD_REQUEST,
        );
    }


    /**
     * What an offer produced: the offer as it is recorded, and a page of the credentials issued from it, each with
     * the identifier the status API takes.
     *
     * Asked by the API caller which made the offer, and by no one else. All of the authorization is settled before
     * anything about the offer is read back or told apart: a bearer token in the Authorization header only (an
     * administrator has the administration screens), one of this endpoint's scopes, the offer made by the principal
     * the token stands for, and every configuration it offered still on the token's list. An offer id which is
     * malformed, unknown, purged, an administrator's, another caller's, or outside the list is answered in one way,
     * 404 `not_found`, so that no caller learns which offer ids exist; the operator's log says which it was.
     *
     * A credential issued without a Status List entry (its configuration uses none) is not listed: the entry is
     * where the link to its offer is kept. Nor is one whose linkage has been cleared since it expired.
     *
     * Credentials come in the order they were issued, CREDENTIALS_PAGE_SIZE at a time, with `next_cursor` to ask
     * for the next page. The cursor names the last credential of a page rather than a position, so that credentials
     * which expire and leave the listing while a caller pages through it do not shift the pages.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function credentialOfferDetails(Request $request, string $offerId): Response
    {
        if (!$this->moduleConfig->getApiVciCredentialOfferEndpointEnabled()) {
            $this->loggerService->warning('Credential Offer API endpoint not enabled.');
            throw OidcServerException::forbidden('Credential Offer API endpoint not enabled.');
        }

        $caller = $this->authorizeOfferCaller($request);

        if ($caller instanceof Response) {
            return $caller;
        }

        $offer = $this->readOfferOf($offerId, $caller);

        if ($offer instanceof Response) {
            return $offer;
        }

        /** @var mixed $cursor */
        $cursor = $request->query->all()[self::PARAM_CURSOR] ?? null;
        $after = null;

        if ($cursor !== null) {
            $after = is_string($cursor) ? $this->decodeCursor($cursor) : null;

            if (!$after instanceof StatusListEntryPosition) {
                return $this->routes->newJsonErrorResponse(
                    error: 'invalid_request',
                    description: sprintf('The cursor (%s) is malformed.', self::PARAM_CURSOR),
                    httpCode: Response::HTTP_BAD_REQUEST,
                );
            }
        }

        try {
            // One more than a page, to know whether there is a next one without counting.
            $entries = $this->statusListEntryRepository->findLinkedToOffer(
                $offer->getId(),
                self::CREDENTIALS_PAGE_SIZE + 1,
                $after,
            );

            $nextCursor = null;

            if (count($entries) > self::CREDENTIALS_PAGE_SIZE) {
                $entries = array_slice($entries, 0, self::CREDENTIALS_PAGE_SIZE);
                $lastEntry = end($entries);

                if (!$lastEntry instanceof StatusListEntryRecord) {
                    throw new RuntimeException('A full page of credentials holds no last credential.');
                }

                $nextCursor = $this->encodeCursor(StatusListEntryPosition::fromRecord($lastEntry));
            }
        } catch (Throwable $exception) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: The credentials of a credential offer could not be read: ' .
                $exception->getMessage(),
            );
            return $this->routes->newJsonErrorResponse(
                error: 'server_error',
                description: 'The credentials of the credential offer could not be read.',
                httpCode: Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }

        $data = [
            'offer_id' => $offer->getId(),
            'credential_configuration_ids' => $offer->getCredentialConfigurationIds(),
            'grant_type' => $offer->getGrantType(),
            'created_at' => $offer->getCreatedAt()->getTimestamp(),
            'redeemable_until' => $offer->getRedeemableUntil()->getTimestamp(),
            'redeemed_at' => $offer->getRedeemedAt()?->getTimestamp(),
            'withdrawn_at' => $offer->getWithdrawnAt()?->getTimestamp(),
            'credentials' => array_map($this->describeCredential(...), $entries),
        ];

        if ($nextCursor !== null) {
            $data['next_cursor'] = $nextCursor;
        }

        return $this->routes->newJsonResponse($data);
    }


    /**
     * Withdraw an offer, so that it buys nothing more: the token endpoint redeems neither its pre-authorized code nor
     * its issuer state, and the Credential Endpoint refuses the access tokens already minted for it, asking once more
     * after the credentials of a request are linked to the offer and before they are handed out. So a listing taken
     * after the withdrawal holds every credential the offer will ever have handed out. Credentials already issued are
     * left as they are: the caller lists them and changes each through the status API.
     *
     * Authorized as the listing is (credentialOfferDetails()), and answered alike for every offer the caller may not
     * see. Withdrawing a withdrawn offer again changes nothing and answers `changed: false`, so a caller retrying a
     * request whose answer it never saw can tell which happened.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function credentialOfferWithdrawal(Request $request, string $offerId): Response
    {
        if (!$this->moduleConfig->getApiVciCredentialOfferEndpointEnabled()) {
            $this->loggerService->warning('Credential Offer API endpoint not enabled.');
            throw OidcServerException::forbidden('Credential Offer API endpoint not enabled.');
        }

        $caller = $this->authorizeOfferCaller($request);

        if ($caller instanceof Response) {
            return $caller;
        }

        $offer = $this->readOfferOf($offerId, $caller);

        if ($offer instanceof Response) {
            return $offer;
        }

        try {
            $changed = $this->credentialOfferRepository->withdraw($offer->getId());
            $withdrawnOffer = $this->credentialOfferRepository->find($offer->getId());
        } catch (Throwable $exception) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: The credential offer could not be withdrawn: ' .
                $exception->getMessage(),
                ['offerId' => $offer->getId()],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'server_error',
                description: 'The credential offer could not be withdrawn.',
                httpCode: Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }

        // Removed by the cron since it was read a moment ago, which takes an offer only once it can buy nothing.
        if (!$withdrawnOffer instanceof CredentialOfferRecord) {
            $this->loggerService->info(
                'VciCredentialOfferApiController: Credential offer removed while it was being withdrawn.',
                ['offerId' => $offer->getId(), 'principal' => $caller->getPrincipal()],
            );
            return $this->offerNotFoundResponse();
        }

        $withdrawnAt = $withdrawnOffer->getWithdrawnAt();

        if (!$withdrawnAt instanceof DateTimeImmutable) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: The credential offer could not be withdrawn: the write did not ' .
                'take.',
                ['offerId' => $offer->getId()],
            );
            return $this->routes->newJsonErrorResponse(
                error: 'server_error',
                description: 'The credential offer could not be withdrawn.',
                httpCode: Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }

        $this->loggerService->notice(
            $changed ?
                'VciCredentialOfferApiController: Credential offer withdrawn.' :
                'VciCredentialOfferApiController: Credential offer asked to be withdrawn was withdrawn already.',
            ['offerId' => $offer->getId(), 'principal' => $caller->getPrincipal()],
        );

        return $this->routes->newJsonResponse([
            'withdrawn_at' => $withdrawnAt->getTimestamp(),
            'changed' => $changed,
        ]);
    }


    /**
     * The caller of an endpoint about one offer, or the answer refusing it. A bearer token in the Authorization
     * header only (an administrator has the administration screens), with one of this endpoint's scopes, answered
     * with the challenge RFC 6750 asks for when it fails.
     */
    protected function authorizeOfferCaller(Request $request): ApiCaller|Response
    {
        try {
            return $this->authorization->requireBearerTokenForAnyOfScope($request, self::SCOPES);
        } catch (InsufficientScopeException $exception) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: InsufficientScopeException: ' . $exception->getMessage(),
            );
            return $this->routes->newJsonErrorResponse(
                error: 'insufficient_scope',
                description: $exception->getMessage(),
                httpCode: Response::HTTP_FORBIDDEN,
                headers: [self::HEADER_WWW_AUTHENTICATE => sprintf(
                    'Bearer error="insufficient_scope", scope="%s"',
                    ApiScopesEnum::VciCredentialOffer->value,
                )],
            );
        } catch (AuthorizationException $exception) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: AuthorizationException: ' . $exception->getMessage(),
            );
            // A request which carried no token gets the bare challenge: RFC 6750 keeps `invalid_token` for a
            // token which actually arrived.
            return $this->routes->newJsonErrorResponse(
                error: 'unauthorized',
                description: $exception->getMessage(),
                httpCode: Response::HTTP_UNAUTHORIZED,
                headers: [self::HEADER_WWW_AUTHENTICATE => $exception instanceof MissingTokenException ?
                    'Bearer' :
                    'Bearer error="invalid_token"',
                ],
            );
        } catch (ConfigurationError $exception) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: API token configuration could not be read: ' .
                $exception->getMessage(),
            );
            return $this->routes->newJsonErrorResponse(
                error: 'server_error',
                description: 'Authorization could not be resolved.',
                httpCode: Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }
    }


    /**
     * The offer when it is this caller's to see, or the answer refusing it: one 404 for every offer the caller may
     * not see (findOfferOf()), and a server error when the offer can not be read.
     */
    protected function readOfferOf(string $offerId, ApiCaller $caller): CredentialOfferRecord|Response
    {
        try {
            $offer = $this->findOfferOf($offerId, $caller);
        } catch (Throwable $exception) {
            $this->loggerService->error(
                'VciCredentialOfferApiController: The credential offer could not be read: ' . $exception->getMessage(),
            );
            return $this->routes->newJsonErrorResponse(
                error: 'server_error',
                description: 'The credential offer could not be read.',
                httpCode: Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }

        return $offer ?? $this->offerNotFoundResponse();
    }


    protected function offerNotFoundResponse(): Response
    {
        return $this->routes->newJsonErrorResponse(
            error: 'not_found',
            description: 'No credential offer with that identifier can be shown.',
            httpCode: Response::HTTP_NOT_FOUND,
        );
    }


    /**
     * The offer, when it is this caller's to see; null for every other case, which the caller is answered alike for
     * and the operator's log tells apart.
     *
     * @throws \RuntimeException When the stored offer can not be read.
     */
    protected function findOfferOf(string $offerId, ApiCaller $caller): ?CredentialOfferRecord
    {
        // Refused before any lookup: no other form is ever stored, and a database whose collation ignores case
        // would otherwise find the offer under spellings it was never given as.
        if (preg_match(self::OFFER_ID_PATTERN, $offerId) !== 1) {
            $this->loggerService->info('VciCredentialOfferApiController: Malformed credential offer ID asked for.');
            return null;
        }

        $offer = $this->credentialOfferRepository->find($offerId);

        if (!$offer instanceof CredentialOfferRecord) {
            $this->loggerService->info(
                'VciCredentialOfferApiController: Unknown or purged credential offer asked for.',
                ['offerId' => $offerId, 'principal' => $caller->getPrincipal()],
            );
            return null;
        }

        if (!$offer->isOwnedBy($caller->getPrincipal())) {
            $this->loggerService->info(
                'VciCredentialOfferApiController: Credential offer asked for by a caller which did not make it.',
                ['offerId' => $offerId, 'principal' => $caller->getPrincipal(), 'owner' => $offer->getOwner()],
            );
            return null;
        }

        // An offer whose configuration has since left the token's list is no longer the token's to see.
        foreach ($offer->getCredentialConfigurationIds() as $credentialConfigurationId) {
            if (!$caller->getCredentialConfigurationLimit()->allows($credentialConfigurationId)) {
                $this->loggerService->info(
                    'VciCredentialOfferApiController: Credential offer asked for by a token which may no longer ' .
                    'act on its credential configuration.',
                    [
                        'offerId' => $offerId,
                        'principal' => $caller->getPrincipal(),
                        'credentialConfigurationId' => $credentialConfigurationId,
                    ],
                );
                return null;
            }
        }

        return $offer;
    }


    /**
     * @return array<string,mixed>
     */
    protected function describeCredential(StatusListEntryRecord $entry): array
    {
        $statusType = $entry->getStatusType();

        return [
            'credential_id' => $entry->getCredentialId(),
            'credential_configuration_id' => $entry->getCredentialConfigurationId(),
            // As the status API names them. A value this module does not name, which it never sets itself, as
            // its number.
            'status' => $statusType instanceof StatusTypeEnum ? strtolower($statusType->name) : $entry->getStatus(),
            'issued_at' => $entry->getIssuedAt()?->getTimestamp(),
            'expires_at' => $entry->getExpiresAt()?->getTimestamp(),
        ];
    }


    /**
     * The cursor is opaque to the caller: the key of the last credential of a page, as JSON, base64url encoded.
     * Nothing is gained by forging one: it is only ever applied within the offer the caller has been allowed to see.
     *
     * @throws \JsonException
     */
    protected function encodeCursor(StatusListEntryPosition $position): string
    {
        return rtrim(strtr(base64_encode(json_encode(
            [
                // In UTC, as the moment is stored and as the cursor is read back.
                $position->getIssuedAt()->setTimezone(new DateTimeZone('UTC'))->format(
                    DateFormatsEnum::DB_DATETIME->value,
                ),
                $position->getStatusListId(),
                $position->getIdx(),
            ],
            JSON_THROW_ON_ERROR,
        )), '+/', '-_'), '=');
    }


    protected function decodeCursor(string $cursor): ?StatusListEntryPosition
    {
        if (preg_match('/^[A-Za-z0-9_-]+$/D', $cursor) !== 1) {
            return null;
        }

        $json = base64_decode(strtr($cursor, '-_', '+/'), true);

        try {
            /** @var mixed $key */
            $key = is_string($json) ? json_decode($json, true, 4, JSON_THROW_ON_ERROR) : null;
        } catch (JsonException) {
            return null;
        }

        // Each component within what its column holds, so that no database is asked to compare a value it refuses
        // (PostgreSQL errors on an INT out of range, and on a year it can not store), which would answer a malformed
        // cursor as this server's failure.
        if (
            !is_array($key) ||
            !array_is_list($key) ||
            count($key) !== 3 ||
            !is_string($key[0]) ||
            !is_string($key[1]) ||
            preg_match(self::CURSOR_STATUS_LIST_ID_PATTERN, $key[1]) !== 1 ||
            !is_int($key[2]) ||
            $key[2] < 0 ||
            $key[2] > self::CURSOR_IDX_MAX
        ) {
            return null;
        }

        // A string carrying a NUL byte is refused by the parser with an error rather than a false.
        try {
            $issuedAt = DateTimeImmutable::createFromFormat(
                '!' . DateFormatsEnum::DB_DATETIME->value,
                $key[0],
                new DateTimeZone('UTC'),
            );
        } catch (ValueError) {
            return null;
        }

        // Read back exactly as written, so that no other spelling of a moment passes for one, and within the years
        // every supported database stores.
        if (
            !$issuedAt instanceof DateTimeImmutable ||
            $issuedAt->format(DateFormatsEnum::DB_DATETIME->value) !== $key[0] ||
            $key[0] < self::CURSOR_MOMENT_MIN ||
            $key[0] > self::CURSOR_MOMENT_MAX
        ) {
            return null;
        }

        return new StatusListEntryPosition($issuedAt, $key[1], $key[2]);
    }
}
