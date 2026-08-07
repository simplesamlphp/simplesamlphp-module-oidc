<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Api;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusChangeSourceEnum;
use SimpleSAML\Module\oidc\Controllers\Api\VciCredentialStatusApiController;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Exceptions\InsufficientScopeException;
use SimpleSAML\Module\oidc\Exceptions\MissingTokenException;
use SimpleSAML\Module\oidc\Exceptions\StatusConflictException;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Exceptions\UnsupportedStatusException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\CredentialStatusService;
use SimpleSAML\Module\oidc\StatusList\Values\CredentialStatusChange;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

#[CoversClass(VciCredentialStatusApiController::class)]
class VciCredentialStatusApiControllerTest extends TestCase
{
    protected const string CREDENTIAL_ID = 'https://issuer.example.org/vc/abc';

    protected const string ACTOR = 'HR system';

    protected MockObject $moduleConfigMock;
    protected MockObject $authorizationMock;
    protected MockObject $credentialStatusServiceMock;
    protected MockObject $routesMock;
    protected MockObject $loggerServiceMock;

    /** @var array<string,mixed> Body of the JSON response the controller produced. */
    protected array $responseData = [];

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getApiEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getApiVciCredentialStatusEndpointEnabled')->willReturn(true);

        $this->authorizationMock = $this->createMock(Authorization::class);
        $this->authorizationMock->method('requireBearerTokenForAnyOfScope')->willReturn(self::ACTOR);

        $this->credentialStatusServiceMock = $this->createMock(CredentialStatusService::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->responseData = [];

        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            function (array $data): JsonResponse {
                $this->responseData = $data;

                return new JsonResponse($data);
            },
        );
        $this->routesMock->method('newJsonErrorResponse')->willReturnCallback(
            static fn(
                string $error,
                string $description,
                int $httpCode = 500,
                array $headers = [],
            ): JsonResponse => new JsonResponse(
                ['error' => $error, 'error_description' => $description],
                $httpCode,
                $headers,
            ),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function sut(): VciCredentialStatusApiController
    {
        return new VciCredentialStatusApiController(
            $this->moduleConfigMock,
            $this->authorizationMock,
            $this->credentialStatusServiceMock,
            $this->routesMock,
            $this->loggerServiceMock,
        );
    }

    /**
     * @param array<string,mixed> $body
     */
    protected function request(array $body = []): Request
    {
        $body = $body === [] ? [
            'credential_id' => self::CREDENTIAL_ID,
            'status' => 'invalid',
        ] : $body;

        $request = new Request([], [], [], [], [], [], (string)json_encode($body));
        $request->setMethod('POST');
        $request->headers->set('Content-Type', 'application/json');

        return $request;
    }

    protected function change(bool $isChanged = true, StatusTypeEnum $status = StatusTypeEnum::Invalid): void
    {
        $this->credentialStatusServiceMock->method('setStatus')->willReturn(
            new CredentialStatusChange('list-1', 42, StatusTypeEnum::Valid->value, $status, $isChanged),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testChangesTheStatus(): void
    {
        $this->change();

        $response = $this->sut()->credentialStatus($this->request());

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
        $this->assertSame('invalid', $this->responseData['status'] ?? null);
        $this->assertTrue($this->responseData['changed'] ?? null);
    }

    /**
     * A caller retrying a request it never saw the answer to needs to be told the credential is
     * revoked, not that it just revoked it a second time.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testARepeatedRequestSucceedsAndSaysNothingChanged(): void
    {
        $this->change(isChanged: false);

        $response = $this->sut()->credentialStatus($this->request());

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
        $this->assertFalse($this->responseData['changed'] ?? null);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testPassesTheAuthorizedPrincipalThroughToTheAuditTrail(): void
    {
        $this->credentialStatusServiceMock->expects($this->once())
            ->method('setStatus')
            ->with(
                self::CREDENTIAL_ID,
                StatusTypeEnum::Invalid,
                StatusChangeSourceEnum::Api,
                self::ACTOR,
            )
            ->willReturn(new CredentialStatusChange('list-1', 42, 0, StatusTypeEnum::Invalid, true));

        $this->sut()->credentialStatus($this->request());
    }

    /**
     * The endpoint's own authorization path, which unlike the rest of this API accepts nothing but a
     * bearer token in the Authorization header.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRequiresABearerTokenCarryingAStatusScope(): void
    {
        $authorization = $this->createMock(Authorization::class);
        $authorization->expects($this->once())
            ->method('requireBearerTokenForAnyOfScope')
            ->with(
                $this->anything(),
                [ApiScopesEnum::VciCredentialStatus, ApiScopesEnum::VciAll, ApiScopesEnum::All],
            )
            ->willReturn(self::ACTOR);
        $this->authorizationMock = $authorization;
        $this->change();

        $this->sut()->credentialStatus($this->request());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRefusesAnUnauthorizedRequestWithoutTouchingAnyStatus(): void
    {
        $authorization = $this->createMock(Authorization::class);
        $authorization->method('requireBearerTokenForAnyOfScope')
            ->willThrowException(new AuthorizationException('Authorization token not provided.'));
        $this->authorizationMock = $authorization;

        $this->credentialStatusServiceMock->expects($this->never())->method('setStatus');

        $this->assertSame(
            Response::HTTP_UNAUTHORIZED,
            $this->sut()->credentialStatus($this->request())->getStatusCode(),
        );
    }

    /**
     * One never issued here, one issued without a status claim and one which has expired are all
     * answered the same way, so that a caller can not learn which identifiers exist.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRespondsNotFoundWhenThereIsNothingToActOn(): void
    {
        $this->credentialStatusServiceMock->method('setStatus')->willReturn(null);

        $this->assertSame(
            Response::HTTP_NOT_FOUND,
            $this->sut()->credentialStatus($this->request())->getStatusCode(),
        );
    }

    /**
     * The number of bits per entry is fixed when a list is created, so this can never succeed and
     * saying so is more use than a 500.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRespondsUnprocessableWhenTheListCanNotCarryTheStatus(): void
    {
        $this->credentialStatusServiceMock->method('setStatus')
            ->willThrowException(new UnsupportedStatusException('one bit per entry'));

        $this->assertSame(
            Response::HTTP_UNPROCESSABLE_ENTITY,
            $this->sut()->credentialStatus($this->request(
                ['credential_id' => self::CREDENTIAL_ID, 'status' => 'suspended'],
            ))->getStatusCode(),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRespondsConflictWhenTheChangeLostToAnother(): void
    {
        $this->credentialStatusServiceMock->method('setStatus')
            ->willThrowException(new StatusConflictException('kept losing'));

        $this->assertSame(
            Response::HTTP_CONFLICT,
            $this->sut()->credentialStatus($this->request())->getStatusCode(),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRespondsServerErrorForAnythingElse(): void
    {
        $this->credentialStatusServiceMock->method('setStatus')
            ->willThrowException(new StatusListException('the database is gone'));

        $response = $this->sut()->credentialStatus($this->request());

        $this->assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
        // Whatever went wrong internally is not the caller's to read.
        $this->assertStringNotContainsString('database', (string)$response->getContent());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRefusesARequestWithoutACredentialIdentifier(): void
    {
        $this->credentialStatusServiceMock->expects($this->never())->method('setStatus');

        $this->assertSame(
            Response::HTTP_BAD_REQUEST,
            $this->sut()->credentialStatus($this->request(['status' => 'invalid']))->getStatusCode(),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRefusesAStatusItDoesNotRecognise(): void
    {
        $this->credentialStatusServiceMock->expects($this->never())->method('setStatus');

        $this->assertSame(
            Response::HTTP_BAD_REQUEST,
            $this->sut()->credentialStatus($this->request(
                ['credential_id' => self::CREDENTIAL_ID, 'status' => 'revoked'],
            ))->getStatusCode(),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testAcceptsEveryStatusTypeByName(): void
    {
        foreach (StatusTypeEnum::cases() as $case) {
            $this->setUp();

            // Captured rather than assumed. Returning the expected status regardless of the argument
            // would let a mapping which turned every suspension into a revocation still pass.
            $requested = null;
            $this->credentialStatusServiceMock->method('setStatus')->willReturnCallback(
                function (string $credentialId, StatusTypeEnum $status) use (&$requested): CredentialStatusChange {
                    $requested = $status;

                    return new CredentialStatusChange('list-1', 42, 0, $status, true);
                },
            );

            $response = $this->sut()->credentialStatus($this->request(
                ['credential_id' => self::CREDENTIAL_ID, 'status' => strtoupper($case->name)],
            ));

            $this->assertSame(
                Response::HTTP_OK,
                $response->getStatusCode(),
                sprintf('Status "%s" was not accepted.', $case->name),
            );
            $this->assertSame($case, $requested, sprintf('Status "%s" was mapped to something else.', $case->name));
            $this->assertSame(strtolower($case->name), $this->responseData['status'] ?? null);
        }
    }

    /**
     * A good token which does not cover this action. Answering 401 would tell the caller its token is
     * bad and invite it to rotate one which is working perfectly well; the fix is a scope only an
     * operator can grant.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRespondsForbiddenWhenTheTokenLacksTheScope(): void
    {
        $authorization = $this->createMock(Authorization::class);
        $authorization->method('requireBearerTokenForAnyOfScope')
            ->willThrowException(new InsufficientScopeException('not authorized for this action'));
        $this->authorizationMock = $authorization;

        $this->credentialStatusServiceMock->expects($this->never())->method('setStatus');

        $response = $this->sut()->credentialStatus($this->request());

        $this->assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
        $this->assertStringContainsString(
            'insufficient_scope',
            (string)$response->headers->get(VciCredentialStatusApiController::HEADER_WWW_AUTHENTICATE),
        );
    }

    /**
     * Without the challenge a client is left to guess that this endpoint wants a bearer token.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testChallengesForABearerTokenWhenNoneWasUsable(): void
    {
        $authorization = $this->createMock(Authorization::class);
        $authorization->method('requireBearerTokenForAnyOfScope')
            ->willThrowException(new AuthorizationException('Authorization token has no scopes.'));
        $this->authorizationMock = $authorization;

        $response = $this->sut()->credentialStatus($this->request());

        $this->assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        $this->assertSame(
            'Bearer error="invalid_token"',
            $response->headers->get(VciCredentialStatusApiController::HEADER_WWW_AUTHENTICATE),
        );
    }

    /**
     * RFC 6750 keeps `invalid_token` for a token which actually arrived. A client told its token was
     * rejected when it never sent one may go and rotate a token which was working.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testChallengesWithoutAnErrorCodeWhenNoTokenWasSent(): void
    {
        $authorization = $this->createMock(Authorization::class);
        $authorization->method('requireBearerTokenForAnyOfScope')
            ->willThrowException(new MissingTokenException('Authorization token not provided.'));
        $this->authorizationMock = $authorization;

        $response = $this->sut()->credentialStatus($this->request());

        $this->assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        $this->assertSame(
            'Bearer',
            $response->headers->get(VciCredentialStatusApiController::HEADER_WWW_AUTHENTICATE),
        );
    }

    public function testIsNotServedWhileTheEndpointIsDisabled(): void
    {
        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('getApiEnabled')->willReturn(true);
        $moduleConfig->method('getVciEnabled')->willReturn(true);
        $moduleConfig->method('getApiVciCredentialStatusEndpointEnabled')->willReturn(false);
        $this->moduleConfigMock = $moduleConfig;

        $this->expectException(OidcServerException::class);

        $this->sut()->credentialStatus($this->request());
    }

    public function testIsNotServedWhileTheApiIsDisabled(): void
    {
        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('getApiEnabled')->willReturn(false);
        $moduleConfig->method('getVciEnabled')->willReturn(true);
        $this->moduleConfigMock = $moduleConfig;

        $this->expectException(OidcServerException::class);

        $this->sut();
    }

    /**
     * Turning issuance off must stop new credentials being issued, not strand the ones already in
     * wallets as impossible to withdraw. Switching issuance off in a hurry is what an operator does
     * during an incident, which is exactly when revocation is needed.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testStillRevokesWhileCredentialIssuanceIsDisabled(): void
    {
        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('getApiEnabled')->willReturn(true);
        $moduleConfig->method('getVciEnabled')->willReturn(false);
        $moduleConfig->method('getApiVciCredentialStatusEndpointEnabled')->willReturn(true);
        $this->moduleConfigMock = $moduleConfig;
        $this->change();

        $this->assertSame(
            Response::HTTP_OK,
            $this->sut()->credentialStatus($this->request())->getStatusCode(),
        );
    }

    /**
     * The request is what is broken, not the server, and a 500 says the opposite.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRefusesABodyItCanNotRead(): void
    {
        $this->credentialStatusServiceMock->expects($this->never())->method('setStatus');

        $request = new Request([], [], [], [], [], [], '{"credential_id": ');
        $request->setMethod('POST');
        $request->headers->set('Content-Type', 'application/json');

        $this->assertSame(
            Response::HTTP_BAD_REQUEST,
            $this->sut()->credentialStatus($request)->getStatusCode(),
        );
    }
}
