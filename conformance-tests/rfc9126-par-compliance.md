# RFC 9126 (PAR) + request_uri — MUST compliance checklist

The OpenID Foundation conformance suite only exercises PAR as part of the
FAPI 2.0 profile (which imposes many unrelated requirements), so it is not a
practical fit for validating PAR on this general-purpose OP. Instead, this
document tracks every normative (MUST / MUST NOT / REQUIRED) requirement from
[RFC 9126](https://www.rfc-editor.org/rfc/rfc9126) — plus the directly related
[RFC 9101 (JAR)](https://www.rfc-editor.org/rfc/rfc9101) request-object
processing rules for the `request` / `request_uri` paths — and maps each to the
code that enforces it and the unit test(s) that prove it.

When you change PAR / request_uri behaviour, keep this table in sync.

## Pushed Authorization Request endpoint (RFC 9126 §2)

| # | Requirement (spec ref) | Enforced in | Covered by test |
|---|------------------------|-------------|-----------------|
| 1 | PAR endpoint URL MUST use the `https` scheme (§2). | Endpoint URL is derived from the module/issuer base URL; HTTPS is a deployment concern. | _Deployment-level_ (issuer/base URL must be HTTPS); not unit-tested. |
| 2 | The AS MUST accept its issuer identifier, token endpoint URL, **or PAR endpoint URL** as the client-assertion audience (§2). | `AuthenticatedOAuth2ClientResolver::forPrivateKeyJwt()` (PAR endpoint URL added to expected audiences). | `AuthenticatedOAuth2ClientResolverTest`: `testForPrivateKeyJwtAcceptsPushedAuthorizationRequestEndpointAsAudience`, `testForPrivateKeyJwtAcceptsIssuerIdentifierAsAudience`, `testForPrivateKeyJwtReturnsResolvedResultOnSuccess` (token endpoint), `testForPrivateKeyJwtThrowsWhenAudienceClaimDoesNotContainExpectedValue`. |

## Request processing (RFC 9126 §2.1)

| # | Requirement (spec ref) | Enforced in | Covered by test |
|---|------------------------|-------------|-----------------|
| 3 | Authenticate the client the same way as at the token endpoint (§2.1, step 1). | `PushedAuthorizationController::__invoke()` via `AuthenticatedOAuth2ClientResolver::forAnySupportedMethod()`; confidential clients must authenticate. | `PushedAuthorizationControllerTest`: `testClientAuthenticationFailureThrows`, `testConfidentialClientMustAuthenticate`. |
| 4 | MUST reject the request if the `request_uri` parameter is provided (§2.1 step 2; §2.1-1 "MUST NOT be provided"). | `PushedAuthorizationController::__invoke()` rejects `request_uri` in the body. | `PushedAuthorizationControllerTest::testRejectsRequestUriInBody`. |
| 5 | MUST validate the pushed request as it would an authorization request at the authorization endpoint (§2.1 step 3). | `PushedAuthorizationController::__invoke()` runs the authorization request-rule pipeline (`StateRule`, `ClientRedirectUriRule`, `RequestObjectRule`, `ResponseModeRule`, `ScopeRule`, `RequiredOpenIdScopeRule`, `CodeChallengeRule`, `CodeChallengeMethodRule`, `DpopJktRule`, `IssuerStateRule`, `AuthorizationDetailsRule`, `OfferedCredentialsRule`); `resolveParametersToPersist()` refuses a request without `response_type`, which nothing could supply at redemption (row 23). | `PushedAuthorizationControllerTest::testHandlesValidParRequest`, `testRefusesAPushedRequestWithoutAResponseType` (and the rule-specific tests for each rule). |

## Successful response (RFC 9126 §2.2)

| # | Requirement (spec ref) | Enforced in | Covered by test |
|---|------------------------|-------------|-----------------|
| 6 | On success the server MUST generate a `request_uri` and return it with HTTP `201` (and `expires_in`). | `PushedAuthorizationController::__invoke()` (201, JSON body with `request_uri` + `expires_in`, `Cache-Control: no-cache, no-store`). | `PushedAuthorizationControllerTest::testHandlesValidParRequest`. |
| 7 | The `request_uri` MUST contain a cryptographically strong pseudorandom part (§2.2; §7.1). | `PushedAuthorizationRequestEntityFactory::fromData()` uses `bin2hex(random_bytes(32))` behind the `urn:ietf:params:oauth:request_uri:` prefix. | `PushedAuthorizationRequestEntityFactoryTest`: `testCanBuildNew` (prefix + 64 hex chars), `testBuildNewGeneratesUniqueRequestUris`. |
| 8 | The `request_uri` value MUST be bound to the client that posted it (§2.2-4). | Entity stores `client_id`; `RequestUriRule` checks the bound client at the authorization endpoint; the controller binds `client_id` to the authenticated client on persist. | `RequestUriRuleTest::testThrowsIfPushedAuthorizationRequestIsBoundToDifferentClient`; `PushedAuthorizationControllerTest::testHandlesValidParRequest` (client_id bound). |

## Error response (RFC 9126 §2.3)

| # | Requirement (spec ref) | Enforced in | Covered by test |
|---|------------------------|-------------|-----------------|
| 9 | Errors MUST use the token-endpoint error format (JSON); the endpoint MUST NOT redirect (§2.3). | `PushedAuthorizationController::par()` catches exceptions → `ErrorResponder::forExceptionJson()` (JSON, never redirects). | `PushedAuthorizationControllerTest`: `testParReturnsJsonErrorResponseForOAuthServerException`, `testParReturnsGenericJsonErrorResponseForUnexpectedThrowable` (also asserts internal details are not leaked). |
| 10 | If signed Request Objects are required (by AS or client policy), the AS MUST only accept §3-compliant requests and MUST refuse others with 400 `invalid_request` (§2.3-2). | `RequestObjectRule` enforces `require_signed_request_object` (module + client); run at the PAR endpoint via the controller pipeline. | `RequestObjectRuleTest`: `testThrowsWhenGlobalRequireSignedRequestObjectIsEnabled`, `testThrowsWhenClientRequireSignedRequestObjectIsEnabled`. |
| 11 | If the request did not use `POST`, respond with HTTP `405` (§2.3). | `PushedAuthorizationController::__invoke()` 405 guard with `Allow: POST`. | `PushedAuthorizationControllerTest::testMethodMustBePost`. |

## The `request` parameter (RFC 9126 §3 — JAR processing)

| # | Requirement (spec ref) | Enforced in | Covered by test |
|---|------------------------|-------------|-----------------|
| 12 | When a Request Object is used, all authorization request parameters MUST appear as claims of the JWT (§3-1; a requirement on the client). | Lenient: the rules validate the Request Object together with the form body, its claims superseding form parameters of the same name (`RequestParamsResolver`), and `PushedAuthorizationController::resolveParametersToPersist()` persists that set, without the client authentication parameters and `request`. A compliant client is unaffected; one which leaves parameters in the form body is redeemed with what was validated (the redemption reads nothing else, row 23). | `PushedAuthorizationControllerTest`: `testPersistsTheFormBodyWithTheRequestObjectClaimsSupersedingItWhenJarIsUsed`, `testPersistsTheFormBodyScopeWithARequestObjectWhichLeavesItOut`. |
| 13 | MUST validate the Request Object signature (§3 step 2). | `RequestObjectRule::verifySignature()` (JWKS via `JwksResolver`). | `RequestObjectRuleTest`: `testThrowsForInvalidRequestObject`, `testReturnsValidRequestObject`, `testReturnsValidJarRequestObjectForOAuth2Request`, `testMissingClientJwksThrows`. |
| 14 | If the client has credentials, MUST reject when the authenticated `client_id` does not match the `client_id` claim in the Request Object (§3 step 3). | `PushedAuthorizationController::resolveParametersToPersist()` (claim vs authenticated client); `RequestObjectRule` (JAR `client_id` claim vs client). | `PushedAuthorizationControllerTest::testRejectsRequestObjectClientIdClaimWhichDoesNotMatchAuthenticatedClient`; `RequestObjectRuleTest::testThrowsForOAuth2RequestWithMismatchedClientIdClaim`. |

## Authorization request using the `request_uri` (RFC 9126 §4)

| # | Requirement (spec ref) | Enforced in | Covered by test |
|---|------------------------|-------------|-----------------|
| 15 | An expired `request_uri` MUST be rejected (§4-3). | `RequestUriRule` checks `isExpired()` (UTC); `PushedAuthorizationRequestRepository::findValid()` also filters expired. | `RequestUriRuleTest::testThrowsIfPushedAuthorizationRequestIsExpired`; `PushedAuthorizationRequestRepositoryTest::testFindValidReturnsNullForExpiredRequestUri`. |
| 16 | `request_uri` is treated as one-time use (§4-3 SHOULD; implemented strictly). | `RequestUriRule` refuses a consumed `request_uri`; `AuthorizationServer::completeAuthorizationRequest()` consumes it when the authorization response is issued (the user agent comes back with it after the login, so it can not be consumed at validation), refusing the response if it was consumed meanwhile; `PushedAuthorizationRequestRepository::consume()` is an atomic `UPDATE … WHERE is_consumed = 0` (replay guard). | `RequestUriRuleTest`: `testThrowsIfPushedAuthorizationRequestIsConsumed`, `testCanUseValidPushedAuthorizationRequestUriWithoutConsumingIt`; `AuthorizationServerTest`: `testConsumesThePushedRequestBeforeTheResponseIsIssued`, `testRefusesToCompleteAPushedRequestWhichIsAlreadyConsumed`; `PushedAuthorizationRequestRepositoryTest`: `testConsumeReturnsTrueOnlyOnce`, `testFindValidReturnsNullForConsumedRequestUri`, `testConsumeInvalidatesCache`. |
| 17 | The AS MUST validate authorization requests arising from a pushed request as it would any other (§4-4). | `RequestParamsResolver` gives the rules the pushed params as the request's (row 23), after which the standard authorization rule pipeline runs on them. | `RequestUriRuleTest::testCanUseValidPushedAuthorizationRequestUriWithoutConsumingIt` (+ the full rule pipeline). |
| 18 | If policy requires PAR (global or per-client), the AS MUST refuse, with `invalid_request`, any authorization request without a PAR `request_uri` (§4-5). | `RequestUriRule` PAR-required check (`getRequirePushedAuthorizationRequests()` module + client). | `RequestUriRuleTest`: `testThrowsIfParIsRequiredGloballyButNotUsed`, `testThrowsIfParIsRequiredForClientButNotUsed`. |
| 23 | The client builds the authorization request with the `request_uri` as RFC 9101 defines (§4-1), and the AS MUST only use the parameters of the request, even where the client repeats them in the query (RFC 9101 §5, §6.3). | `RequestParamsResolver::resolveParams()` redeems a PAR `request_uri` with the pushed params only; of the front-channel params it keeps `client_id` (the pushed one supersedes it, and `RequestUriRule` refuses one naming another client) and `request_uri`, and ignores every other one, repeated or not. `RequestUriRule` logs at notice the names of ignored params the pushed request does not carry. A `request_uri` sent with `request` is redeemed the same way, whatever the `request` value (null included), and `RequestUriRule` refuses the two together. The token and end session endpoints mark their requests (`RequestParamsResolver::ATTRIBUTE_OWN_PARAMS_ONLY`), so a `request_uri` sent there is ignored rather than redeemed (RFC 6749 §3.2). | `RequestParamsResolverTest`: `testRedeemsAPushedAuthorizationRequestUriWithThePushedParamsOnly`, `testIgnoresParamsSentWithAPushedRequestUriWhichThePushedRequestLacks`, `testAPushedClientIdSupersedesTheOneSentWithTheRequestUri`, `testGetAllResolvesOnlyTheClientIdAndRequestUriForInvalidPushedAuthorizationRequestUri`, `testRedeemsAPushedRequestUriWithThePushedParamsOnlyNextToARequestParam`, `testReadsTheOwnParamsOnlyOfARequestMarkedSoWhateverRequestUriItCarries`; `AccessTokenControllerTest::testHandsARequestWithoutAProofToTheGrantsReadAsItWasSent`; `EndSessionControllerTest::testValidatesTheLogoutRequestReadAsItWasSent`; `RequestUriRuleTest`: `testLogsTheNamesOfParamsSentWithAPushedRequestUriWhichThePushedRequestLacks`, `testLogsNothingForParamsThePushedRequestRepeats`. |

## Authorization server metadata (RFC 9126 §5)

| # | Requirement (spec ref) | Enforced in | Covered by test |
|---|------------------------|-------------|-----------------|
| 19 | Publish `pushed_authorization_request_endpoint` and `require_pushed_authorization_requests` (§5; §2-2 SHOULD). Also `request_uri_parameter_supported` and `require_request_uri_registration` (OIDC Discovery). | `OpMetadataService` populates all four. | `OpMetadataServiceTest` (asserts `pushed_authorization_request_endpoint`, `require_pushed_authorization_requests`, `request_uri_parameter_supported`, `require_request_uri_registration`). |

## Security considerations (RFC 9126 §7)

| # | Requirement (spec ref) | Enforced in | Covered by test |
|---|------------------------|-------------|-----------------|
| 20 | The AS MUST only accept new (unregistered) redirect URIs from authenticated clients (§7.2, open redirection). | The module never accepts unregistered redirect URIs: `ClientRedirectUriRule` always exact-matches the client's registered redirect URIs, and the PAR endpoint always authenticates the client. Compliant by being strict (the §2.4 per-request redirect-URI relaxation is intentionally **not** implemented). | `ClientRedirectUriRuleTest` (redirect URI exact matching). |

## Related request-object claim validation (RFC 9101 / RFC 7519)

Not strictly RFC 9126, but part of the same `request` / `request_uri` feature:

| # | Requirement | Enforced in | Covered by test |
|---|-------------|-------------|-----------------|
| 21 | A JAR (non-OIDC) Request Object MUST be signed; an unsigned object is rejected (RFC 9101). | `RequestObjectRule` requires a `Jar\RequestObject` from the parsed bag for non-OIDC (no `openid` scope) requests. | `RequestObjectRuleTest::testThrowsForOAuth2RequestWithNonJarRequestObject`. |
| 22 | When present, the Request Object `aud` claim must include this OP's issuer, and `iss` must equal the client (RFC 9101 §4, RFC 7519; "validate-if-present"). | `RequestObjectRule::verifyAudience()` / `verifyIssuer()` (OIDC Core + JAR flavors). | `RequestObjectRuleTest`: `testAcceptsOidcRequestWhenAudienceIncludesIssuer`, `testThrowsForOidcRequestWhenAudienceDoesNotIncludeIssuer`, `testThrowsForOAuth2RequestWhenAudienceDoesNotIncludeIssuer`, `testAcceptsOidcRequestWhenIssuerMatchesClient`, `testThrowsForOidcRequestWhenIssuerDoesNotMatchClient`, `testThrowsForOAuth2RequestWhenIssuerDoesNotMatchClient`. |

## Intentionally not implemented (RFC 9126 MAY / optional)

These are optional and deliberately left out; revisit if requirements change:

- **413 Payload Too Large** for oversized PAR bodies (§2.3) — MAY. (Note:
  `request_uri_max_size_bytes` caps the _outbound_ remote `request_uri` fetch,
  not the inbound PAR body.)
- **429 Too Many Requests** rate limiting on the PAR endpoint (§2.3) — MAY.
- **Per-request unregistered `redirect_uri`** for authenticated clients
  (§2.4) — MAY relaxation; the module keeps strict exact-match instead.
