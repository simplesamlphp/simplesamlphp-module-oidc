<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Api;

use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusChangeSourceEnum;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Exceptions\InsufficientScopeException;
use SimpleSAML\Module\oidc\Exceptions\MissingTokenException;
use SimpleSAML\Module\oidc\Exceptions\StatusConflictException;
use SimpleSAML\Module\oidc\Exceptions\UnsupportedStatusException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\CredentialStatusService;
use SimpleSAML\Module\oidc\StatusList\Values\CredentialStatusChange;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Withdraws, suspends or reinstates an issued Verifiable Credential.
 *
 * This is the counterpart to the Status List endpoint: that one publishes what the statuses are, this
 * one is how they come to be what they are.
 *
 * Its authorization is its own, and is the part to read before changing anything here. It takes a
 * bearer token from the Authorization header and nothing else, where the rest of this module's API also
 * accepts an administrator's session and a token given as a request parameter. Both of those are
 * reasonable for the endpoints they serve and neither is reasonable here, for reasons set out on
 * {@see \SimpleSAML\Module\oidc\Services\Api\Authorization::requireBearerTokenForAnyOfScope()}.
 *
 * Deliberately not gated on the Verifiable Credential Issuance switch, unlike the other endpoints in
 * that family and for the same reason the Status List endpoint is not
 * ({@see \SimpleSAML\Module\oidc\Controllers\StatusListController}). Turning issuance off has to stop
 * new credentials being issued; it must not strand the ones already in wallets as impossible to
 * withdraw. If anything the two go together: switching issuance off in a hurry is exactly what an
 * operator does during an incident, which is exactly when the credentials already out there need
 * revoking. Its own switch, and the module API switch, are what govern whether this is served.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Controllers\Api\VciCredentialStatusApiControllerTest
 */
class VciCredentialStatusApiController
{
    final public const string PARAM_CREDENTIAL_ID = 'credential_id';

    final public const string PARAM_STATUS = 'status';

    final public const string HEADER_WWW_AUTHENTICATE = 'WWW-Authenticate';


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Authorization $authorization,
        protected readonly CredentialStatusService $credentialStatusService,
        protected readonly Routes $routes,
        protected readonly LoggerService $loggerService,
    ) {
        if (!$this->moduleConfig->getApiEnabled()) {
            $this->loggerService->warning('API capabilities not enabled.');
            throw OidcServerException::forbidden('API capabilities not enabled.');
        }
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function credentialStatus(Request $request): Response
    {
        if (!$this->moduleConfig->getApiVciCredentialStatusEndpointEnabled()) {
            $this->loggerService->warning('Credential Status API endpoint not enabled.');
            throw OidcServerException::forbidden('Credential Status API endpoint not enabled.');
        }

        try {
            $actorRef = $this->authorization->requireBearerTokenForAnyOfScope(
                $request,
                [ApiScopesEnum::VciCredentialStatus, ApiScopesEnum::VciAll, ApiScopesEnum::All],
            );
        } catch (InsufficientScopeException $exception) {
            // The caller is who it says it is and this is not theirs to do. Answering 401 would invite
            // it to rotate a token that is working perfectly well; the fix is a scope in the
            // configuration, which only an operator can make.
            $this->loggerService->error(
                'VciCredentialStatusApiController: InsufficientScopeException: ' . $exception->getMessage(),
            );

            return $this->routes->newJsonErrorResponse(
                error: 'insufficient_scope',
                description: $exception->getMessage(),
                httpCode: Response::HTTP_FORBIDDEN,
                headers: [self::HEADER_WWW_AUTHENTICATE => sprintf(
                    'Bearer error="insufficient_scope", scope="%s"',
                    ApiScopesEnum::VciCredentialStatus->value,
                )],
            );
        } catch (AuthorizationException $exception) {
            $this->loggerService->error(
                'VciCredentialStatusApiController: AuthorizationException: ' . $exception->getMessage(),
            );

            // The challenge is what tells a client this endpoint wants a bearer token, rather than
            // leaving it to guess from a bare 401. A request which carried no token gets the bare
            // challenge: RFC 6750 keeps `invalid_token` for a token which actually arrived, and a
            // client told its token was rejected when it never sent one may rotate a working one.
            return $this->routes->newJsonErrorResponse(
                error: 'unauthorized',
                description: $exception->getMessage(),
                httpCode: Response::HTTP_UNAUTHORIZED,
                headers: [self::HEADER_WWW_AUTHENTICATE => $exception instanceof MissingTokenException ?
                    'Bearer' :
                    'Bearer error="invalid_token"',
                ],
            );
        }

        try {
            $input = $request->getPayload()->all();
        } catch (Throwable) {
            // A body which is not parseable at all. Left to propagate it would surface as a 500,
            // telling the caller the server broke when in fact its request did.
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: 'Request body could not be read.',
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        /** @var mixed $credentialId */
        $credentialId = $input[self::PARAM_CREDENTIAL_ID] ?? null;

        if (!is_string($credentialId) || trim($credentialId) === '') {
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: sprintf('No credential identifier (%s) provided.', self::PARAM_CREDENTIAL_ID),
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        /** @var mixed $requestedStatus */
        $requestedStatus = $input[self::PARAM_STATUS] ?? null;
        $status = is_string($requestedStatus) ? $this->resolveStatus($requestedStatus) : null;

        if (!$status instanceof StatusTypeEnum) {
            return $this->routes->newJsonErrorResponse(
                error: 'invalid_request',
                description: sprintf(
                    'Status (%s) must be one of: %s.',
                    self::PARAM_STATUS,
                    implode(', ', $this->supportedStatuses()),
                ),
                httpCode: Response::HTTP_BAD_REQUEST,
            );
        }

        try {
            $change = $this->credentialStatusService->setStatus(
                trim($credentialId),
                $status,
                StatusChangeSourceEnum::Api,
                $actorRef,
            );
        } catch (UnsupportedStatusException $exception) {
            // Permanent: the number of bits per entry is fixed when a list is created, so no amount of
            // retrying will make this list able to carry the status. Saying so is more use than a 500.
            $this->loggerService->error(
                'VciCredentialStatusApiController: requested status can not be represented: ' .
                $exception->getMessage(),
            );

            return $this->routes->newJsonErrorResponse(
                error: 'unsupported_status',
                description: $exception->getMessage(),
                httpCode: Response::HTTP_UNPROCESSABLE_ENTITY,
            );
        } catch (StatusConflictException $exception) {
            // The credential ended up holding something other than what was asked for, so reporting
            // success would say a credential was withdrawn when it was not.
            $this->loggerService->error(
                'VciCredentialStatusApiController: status change lost to concurrent changes: ' .
                $exception->getMessage(),
            );

            return $this->routes->newJsonErrorResponse(
                error: 'conflict',
                description: $exception->getMessage(),
                httpCode: Response::HTTP_CONFLICT,
            );
        } catch (Throwable $exception) {
            $this->loggerService->error(
                'VciCredentialStatusApiController: unable to change the credential status: ' .
                $exception->getMessage(),
            );

            return $this->routes->newJsonErrorResponse(
                error: 'server_error',
                description: 'Unable to change the credential status.',
                httpCode: Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }

        if (!$change instanceof CredentialStatusChange) {
            // One that was never issued here, one issued without a status claim and one which has
            // expired are all answered this way. Telling them apart would let a caller enumerate which
            // credential identifiers exist.
            return $this->routes->newJsonErrorResponse(
                error: 'not_found',
                description: 'No credential with that identifier can have its status changed.',
                httpCode: Response::HTTP_NOT_FOUND,
            );
        }

        return $this->routes->newJsonResponse([
            self::PARAM_STATUS => strtolower($change->getStatus()->name),
            // Distinguishes doing it from finding it already done, so a caller retrying a request it
            // never saw the answer to can tell which happened.
            'changed' => $change->isChanged(),
        ]);
    }


    /**
     * The status names this endpoint accepts, which are the Status Type names in lower case.
     *
     * Matched case insensitively, since the names are the interface and quibbling over capitalization
     * would only produce confusing rejections.
     */
    protected function resolveStatus(string $status): ?StatusTypeEnum
    {
        foreach (StatusTypeEnum::cases() as $case) {
            if (strcasecmp($case->name, trim($status)) === 0) {
                return $case;
            }
        }

        return null;
    }


    /**
     * @return string[]
     */
    protected function supportedStatuses(): array
    {
        return array_map(
            static fn(StatusTypeEnum $case): string => strtolower($case->name),
            StatusTypeEnum::cases(),
        );
    }
}
