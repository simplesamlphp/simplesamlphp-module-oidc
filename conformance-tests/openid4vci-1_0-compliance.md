# OpenID4VCI 1.0 issuer compliance (with HAIP 1.0 and FAPI 2.0)

This document maps the issuer-side requirements of
[OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
(OpenID4VCI) to the code that meets them and the unit tests that pin them, and marks what the module does not
implement. It also covers the issuer delta of the
[OpenID4VC High Assurance Interoperability Profile 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)
(HAIP), including the [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
provisions which HAIP section 4 applies.

Every sentence of OpenID4VCI 1.0 sections 3 to 15 and Appendices A to F carrying a requirement keyword was
mapped, as was every one of HAIP 1.0 and of FAPI 2.0 sections 5 and 6, together with the few normative
statements written without one (the token error codes of §6.3, the authorization errors of §8.3.1.1, the one
credential per key of §8.3). The tables keep those which bind the Credential Issuer or its Authorization
Server, and those binding the Wallet which the issuer is expected to check. Requirements binding only the
Wallet, a Verifier, an ecosystem or a trust framework are left out, as are definitions. Related requirements
share a row.

The OpenID Foundation conformance suite's OpenID4VCI issuer plan exercises the flows end to end (see
[docs/5-oidc-conformance.md](../docs/5-oidc-conformance.md)). PAR is mapped in detail in
[rfc9126-par-compliance.md](rfc9126-par-compliance.md).

When you change issuance behaviour, keep this document in sync.

Status values:

- **Met**: the module does it, and a unit test pins it.
- **Met, untested**: the module does it, and no unit test pins it (or the tests pin only part of it; the row
  says which).
- **Config**: met or not depending on configuration or on the deployment (the row names the option and its
  default).
- **Partial**: met in part; the row says what is missing.
- **Gap**: not met. Gaps are listed again, numbered, at the end.
- **Not implemented**: an optional feature the module does not implement, and does not advertise.

## What the module implements

| Feature (spec ref) | Implemented | How it is advertised |
|--------------------|-------------|----------------------|
| Authorization Code Flow, wallet and issuer initiated (§3.4, §5) | Yes | `grant_types_supported` in the AS metadata |
| Pre-Authorized Code Flow, with a Transaction Code delivered by e-mail (§3.5, §6.1) | Yes | `urn:ietf:params:oauth:grant-type:pre-authorized_code` in `grant_types_supported` |
| Credential Offer by value (§4.1.2) | Yes: the offer API and the admin test page build `openid-credential-offer://` URIs | n/a |
| Credential Offer by reference (§4.1.3); the wallet's `credential_offer_endpoint` (§12.1) | No | n/a |
| `authorization_details` of type `openid_credential` (§5.1.1, §6.1.1) | Yes, with the limits of rows 9 to 11, 22 and 23 | Not advertised: no `authorization_details_types_supported` (G16) |
| `scope` per Credential Configuration (§5.1.2) | Yes | `scope` in `credential_configurations_supported`, `scopes_supported` |
| Pushed Authorization Requests (§5.1.4) | Yes ([RFC 9126 matrix](rfc9126-par-compliance.md)) | `pushed_authorization_request_endpoint` |
| DPoP (§13.2, RFC 9449) | Yes; required for issuance with `vci_require_dpop` (default `false`) | `dpop_signing_alg_values_supported` |
| Nonce Endpoint (§7) | Yes | `nonce_endpoint` |
| Credential Endpoint with batch issuance (§8, §3.3.2) | Yes, up to 8 proofs | `credential_endpoint`, `batch_credential_issuance` |
| Formats: `dc+sd-jwt` (A.3), `jwt_vc_json` (A.1.1) | Yes | `credential_configurations_supported` |
| Format `vc+sd-jwt` (W3C VCDM 2.0 secured with SD-JWT) | Yes, as an extension: not an Appendix A profile | `credential_configurations_supported` |
| Formats `ldp_vc`, `jwt_vc_json-ld`, `mso_mdoc` (A.1.2, A.1.3, A.2) | No | Only if an administrator configures one: it is then published as written and fails at issuance (G7) |
| Proof type `jwt` with a `kid` (DID URL) or `jwk` key (F.1) | Yes | `proof_types_supported` |
| Proof types `di_vp`, `attestation`; the `x5c` header of `jwt` proofs (F.1-F.3) | No: refused | Not advertised |
| The `key_attestation` and `trust_chain` headers of `jwt` proofs (F.1, D) | No: ignored, not refused (G17) | Not advertised |
| Token Status Lists in issued credentials | Yes, when enabled | The `status` claim of the credential |
| Deferred Credential Endpoint (§9), Notification Endpoint (§11) | No | Not advertised |
| Encrypted requests and responses (§10) | No: encryption parameters in a request are ignored | Not advertised |
| Signed Credential Issuer Metadata (§12.2.3), `authorization_servers` (§12.2.4) | No | Not advertised; the OP is the only AS |
| Wallet Attestations (Appendix E), key attestations (Appendix D) | No | Not advertised |

## Credential Offer (§4)

| # | Requirement (spec ref) | Status | Enforced in | Covered by test |
|---|------------------------|--------|-------------|-----------------|
| 1 | An offer carries `credential_offer` or `credential_offer_uri`, never both (§4.1). | Met | `CredentialOfferUriFactory::buildUri()`; the module sends offers by value only. | `CredentialOfferUriFactoryTest`: `testByValueOfferSurvivesQueryParsing`, `testByReferenceOfferSurvivesQueryParsing`. |
| 2 | `credential_issuer`, and `credential_configuration_ids`: a non-empty array of unique strings naming configurations in the metadata (§4.1.1). | Partial (G19) | An empty list is refused (`CredentialOfferUriFactory::buildPreAuthorized()`, and the openid library's `CredentialOfferFactory` for both flows). `buildPreAuthorized()` refuses unsupported ids; `buildForAuthorization()` leaves that to its callers (the offer API refuses an unsupported id). Neither refuses a repeated id. The `credential_issuer` value: row 41. | `CredentialOfferUriFactoryTest`: `testBindsThePreAuthorizedCodeToTheResolvedUserAndOffersIt`, `testRefusesAPreAuthorizedOfferForCredentialConfigurationsItCannotOffer`. |
| 3 | `issuer_state` binds the authorization request to the offer, and is not assumed to come from this issuer (§4.1.1, §5.1.3). | Met | `CredentialOfferUriFactory::buildForAuthorization()` persists it; `IssuerStateRule` accepts only a known, redeemable one. | `CredentialOfferUriFactoryTest::testOffersForAuthorizationTheIssuerStateItPersisted`; `IssuerStateRuleTest`: `testCarriesAnIssuerStateWhoseOfferCanStillBeRedeemed`, `testRefusesAnIssuerStateWhoseOfferCanNotBeRedeemedBackToARegisteredClient`. |
| 4 | The `pre-authorized_code` is short-lived and single use (§4.1.1, §3.5). | Met | `PreAuthCodeGrant::respondToAccessTokenRequest()` (atomic consumption, expiry, replay refusal). | `PreAuthCodeGrantTest`: `testRedeemsPreAuthorizedCodeOnlyAfterAtomicConsumption`, `testRefusesAnExpiredPreAuthorizedCode`, `testRejectsReplayBeforeIssuingAnotherAccessToken`. |
| 5 | A `tx_code` object in the offer means a Transaction Code is required (§4.1.1); mitigations against code replay suit the use case (§3.5, §13.6). | Met; the attempt limit is Config | `CredentialOfferUriFactory::buildPreAuthorized()` (code by e-mail, not in the offer); `PreAuthCodeGrant`. `TxCodeAttemptLimiter` limits wrong codes (`vci_tx_code_max_attempts`) only with a protocol cache (`protocol_cache_adapter`, none by default), and counts attempts one after another: concurrent ones can share the last remaining attempt. | `CredentialOfferUriFactoryTest::testSendsTheTransactionCodeByEmailAndKeepsItOutOfTheOffer`; `PreAuthCodeGrantTest::testRefusesEveryTransactionCodeOnceNoAttemptsAreLeft` (the limiter mocked); `TxCodeAttemptLimiterTest`. |
| 6 | The `tx_code` `description` MUST NOT exceed 300 characters (§4.1.1). | Gap (G3) | `CredentialOfferUriFactory::buildPreAuthorized()` writes a fixed 57-character sentence followed by the user's e-mail address, without a length check: an address longer than 243 characters breaks the limit. | `CredentialOfferUriFactoryTest::testBuildTxCodePassesACodeAndDescriptionGivenToItThrough` (pass-through only). |
| 7 | `authorization_server` only where `authorization_servers` has several entries (§4.1.1). | Met, untested | Never emitted: the OP is the only Authorization Server. | - |
| 8 | The issuer ensures that privacy-sensitive data in an offer is released lawfully (§13.5). | Config | The deployment's. The `tx_code` description carries the user's e-mail address into the offer (G3, O1). | - |

## Authorization Endpoint (§5)

| # | Requirement (spec ref) | Status | Enforced in | Covered by test |
|---|------------------------|--------|-------------|-----------------|
| 9 | `authorization_details` of type `openid_credential` with a `credential_configuration_id` naming a configuration in the metadata (§5.1.1). | Partial (G9) | `AuthorizationDetailsRule` refuses a detail without `type`, of another type, or without `credential_configuration_id`; `OfferedCredentialsRule` holds an offer's request to what was offered. Without `issuer_state` nothing checks the id against the metadata, and a value which is not JSON, not an array or empty is dropped without an error. | `AuthorizationDetailsRuleTest`: `testRefusesADetailWithNoType`, `testRefusesADetailWithAnUnknownType`, `testRefusesADetailWithNoCredentialConfigurationId`; `OfferedCredentialsRuleTest::testRefusesAnAuthorizationDetailForAConfigurationTheOfferDidNotOffer`. |
| 10 | A credential `scope` and `authorization_details` in one request are interpreted individually; for the same type, the authorization detail is followed (§5.1.2). | Partial (G10) | The token is granted both, but once it carries authorization details the Credential Endpoint requires a `credential_identifier` and knows only the configurations in those details (`CredentialIssuerCredentialController::issueCredential()`), so a configuration requested by scope alone can not be fetched. | `CredentialIssuerCredentialControllerTest::testRefusesWhenAuthorizationDetailsRequireACredentialIdentifierAndNoneWasSent`. |
| 11 | `claims` in an authorization detail: a non-empty array of claims description objects, each `path` a valid claims path pointer; processing aborts on repeated or contradictory descriptions (§5.1.1, B.1, B.3). | Gap (G5) | `AuthorizationDetailsRule` checks neither the structure nor duplicates. The credential is issued with every configured claim whatever was asked, and the token response returns the detail, `claims` included, as sent (`TokenResponse::prepareVciAuthorizationDetailsExtraParam()`). | - |
| 12 | Unknown scope values are ignored (§5.1.2). | Gap (G1) | `ScopeRule` refuses an unknown scope with `invalid_scope`. | `ScopeRuleTest::testInvalidScopeThrows` (pins the refusal). |
| 13 | Scope values are collision-resistant (§5.1.2, RECOMMENDED). | Config | The configuration ids, which the scopes equal; the module checks only their syntax. | - |
| 14 | The AS ignores unrecognized request parameters (§5.1.3). | Met, untested | The request rules read the parameters they know. | - |
| 15 | PKCE and PAR are RECOMMENDED for the authorization code flow (§5, §5.1.4). | Config | PKCE: `CodeChallengeRule` requires it of public clients only. PAR: supported; required with `require_pushed_authorization_requests` (default `false`) or per client. | `CodeChallengeRuleTest::testRefusesAPublicClientWhichSendsNoCodeChallenge`; `RequestUriRuleTest::testThrowsIfParIsRequiredGloballyButNotUsed`. |
| 16 | Authorization responses and error responses as in RFC 6749 (§5.2, §5.3), with `iss` (RFC 9207). | Partial (G9) | `AuthCodeGrant::completeAuthorizationRequest()`; `AuthorizationController::addIssuerToRedirectedError()`. A malformed authorization detail is answered with a bare 400 `invalid_request` rather than redirected back with `state` and `iss`, and RFC 9396 section 5 names `invalid_authorization_details` for it. | `AuthCodeGrantTest::testNamesItselfAsTheIssuerInTheAuthorizationResponse`; `AuthorizationControllerTest::testAddsTheIssuerToAnErrorRedirectedBackToTheClient`. |

## Token Endpoint (§6)

| # | Requirement (spec ref) | Status | Enforced in | Covered by test |
|---|------------------------|--------|-------------|-----------------|
| 17 | `pre-authorized_code` is present for the pre-authorized code grant (§6.1). | Met | `PreAuthCodeGrant::respondToAccessTokenRequest()`. | `PreAuthCodeGrantTest::testRefusesATokenRequestWithoutAPreAuthorizedCode`. |
| 18 | `tx_code` is present when the offer carried a `tx_code` object, and only then; `invalid_request` for a missing or unexpected code, `invalid_grant` for a wrong code or a wrong or expired pre-authorized code (§6.1, §6.3). | Met | `PreAuthCodeGrant::respondToAccessTokenRequest()`. | `PreAuthCodeGrantTest`: `testRequiresTheTransactionCodeWhenTheCodeCarriesOne`, `testRefusesATransactionCodeForACodeWhichCarriesNone`, `testRejectsInvalidTransactionCodeWithoutConsumingPreAuthorizedCode`, `testRefusesAnExpiredPreAuthorizedCode`. |
| 19 | Client authentication is OPTIONAL for the pre-authorized code grant (§6.1); anonymous access, its `invalid_client` refusal and its metadata flag (§6.3, §12.3). | Partial (G4) | `PreAuthorizedCodeClientRule` serves credentials, a registered client's `client_id`, a non-registered wallet's `client_id`, or nothing (anonymous). Anonymous access is always accepted, but `pre-authorized_grant_anonymous_access_supported` is not published (`OpMetadataService`), so a wallet reads the default, `false`. | `PreAuthorizedCodeClientRuleTest::testAnonymousRequestIdentifiesNobodyAndAsksNothingOfTheResolverOrTheRegistry`; `PreAuthCodeGrantTest::testIssuesTheAccessTokenForTheCodeHolderToTheWalletOrTheCodesClient`. |
| 20 | The requirements of RFC 6749 sections 4.1.3 and 3.2.1 are followed (§6.1), with the error codes of its section 5.2 (§6.3), and the response states `scope` where the grant narrowed it (RFC 6749 section 5.1). | Partial (G23) | `AuthCodeGrant::respondToAccessTokenRequest()` refuses a code issued to another client, a redirect URI which differs from the authorization request's and a code it can not decrypt, but with `invalid_request` rather than `invalid_grant`; a request presenting no client authentication where one is required gets `access_denied` (`ClientAuthenticationRule`) rather than `invalid_client`. The token response never carries `scope`, also when the client's allowed scopes narrowed the request (`ScopeRepository`). | `AuthCodeGrantTest`: `testRejectsAuthorizationCodeIssuedToAnotherClient` (pins `invalid_request`), `testRevokesRelatedTokensWhenAuthorizationCodeIsReplayed`. |
| 21 | A pre-authorized code's access token is valid only for the offered credentials (§6.1, RECOMMENDED). | Met | `PreAuthCodeGrant::offeredScopes()`. | `PreAuthCodeGrantTest::testGrantsTheOfferedConfigurationsTheClientMayHave`. |
| 22 | `authorization_details` in the token request may name a subset of the authorized configurations (§6.1.1, RECOMMENDED); when they are used there, the token response MUST carry `authorization_details` (§6.2). | Partial (G6) | The pre-authorized code grant narrows the token to them (`PreAuthCodeGrant::scopesRequestedByAuthorizationDetails()`). The authorization code grant reads only the authorization details stored with the code, so a code authorized by scope and redeemed with `authorization_details` gets a response without them. | `PreAuthCodeGrantTest::testNarrowsTheTokenToTheConfigurationsTheAuthorizationDetailsName`. |
| 23 | The token response carries the granted `authorization_details`, each with a non-empty `credential_identifiers`, when the request used them (§6.2). | Partial (G11) | `TokenResponse::prepareVciAuthorizationDetailsExtraParam()`, one Credential Dataset per configuration, identified by the configuration id. It returns every stored detail, including one for a configuration the client may not have, whose scope the grant dropped; the Credential Endpoint then refuses it. | `TokenResponseTest::testCarriesTheNormalizedAuthorizationDetailsInAVciFlow`. |
| 24 | The AS ignores unrecognized token request parameters (§6.1). | Met, untested | The grants read the parameters they know. | - |

## Nonce Endpoint (§7)

| # | Requirement (spec ref) | Status | Enforced in | Covered by test |
|---|------------------------|--------|-------------|-----------------|
| 25 | An issuer requiring `c_nonce` in proofs offers a Nonce Endpoint, published as `nonce_endpoint` (§7; HAIP §4.1). | Met | `NonceController::nonce()`; `CredentialIssuerMetadataService`. | `NonceControllerTest::testNonce`; `CredentialIssuerMetadataServiceTest::testPublishesTheIssuerAndItsEndpoints`. |
| 26 | `c_nonce` values are unpredictable, and the response carries `Cache-Control: no-store` (§7.2). | Met | `NonceService::generateNonce()`; `NonceController::nonce()`. | `NonceServiceTest::testGenerateNonce`; `NonceControllerTest::testNonce`. |

## Credential Endpoint (§8)

| # | Requirement (spec ref) | Status | Enforced in | Covered by test |
|---|------------------------|--------|-------------|-----------------|
| 27 | The Credential Endpoint is supported, over TLS (§8). | Met; TLS is Config | `CredentialIssuerCredentialController::credential()`; TLS is the web server's. | `CredentialIssuerCredentialControllerTest::testChecksTheTokenForThePublishedCredentialEndpoint`. |
| 28 | `credential_identifier` when the token response returned authorization details, `credential_configuration_id` otherwise, never both (§8.2). | Partial (G12) | `CredentialIssuerCredentialController::issueCredential()` enforces the first, and the third for non-null values: a member set to `null` next to the other passes. A request carrying neither is still served: the configuration is resolved from the pre-final `format` with `credential_definition.type` or `vct`, and a format it does not know is answered with the pre-final `unsupported_credential_type`. | `CredentialIssuerCredentialControllerTest`: `testRefusesACredentialConfigurationIdSentTogetherWithACredentialIdentifier`, `testRefusesWhenAuthorizationDetailsRequireACredentialIdentifierAndNoneWasSent`, `testRefusesACredentialIdentifierForAFlowWhichWasIssuedNone`, `testRefusesAnUnknownCredentialConfiguration`; the fallback: `testResolvesTheConfigurationFromTheCredentialDefinitionType`, `testResolvesTheConfigurationFromTheVct`. |
| 29 | `proofs` holds exactly one proof type with a non-empty array, is present when the configuration advertises `proof_types_supported`, and holds no more than `batch_size` proofs (§8.2, App. F). | Met | `OpenId4VciProofValidator::extractProofJwts()`. | `OpenId4VciProofValidatorTest`: `testRefusesAnEnvelopeNamingMoreThanOneProofType`, `testRefusesAnEnvelopeWhoseProofsAreNotANonEmptyList`, `testRefusesAProofBoundRequestWhichCarriesNoProof`, `testRefusesAnUnsupportedProofType`, `testRefusesMoreProofsThanTheAdvertisedBatchSize`. |
| 30 | Each proof names the Credential Issuer as its audience and carries a `c_nonce` from the Nonce Endpoint (§8.2, F.1). | Partial (G21) | `OpenId4VciProofValidator` (audience and nonce checks). A `c_nonce` is a JWS signed with the credential signing key, and `NonceService::validateNonce()` checks only its signature, `iss` and `exp`: with an https issuer identifier, a credential this issuer signed, still unexpired, also passes as a nonce, and keeps a proof valid for as long as the credential. | `OpenId4VciProofValidatorTest`: `testRefusesAnAudienceWhichDoesNotNameThisIssuer`, `testRefusesAProofCarryingNoAudience`, `testRefusesAProofCarryingNoNonce`, `testAnswersAStaleNonceWithItsOwnErrorCode`. |
| 31 | The issued credential SHOULD be bound to the key the proof proves (§8.1). | Met | `CredentialIssuerCredentialController::issueCredential()` (`cnf`). | `CredentialIssuerCredentialControllerTest`: `testBindsTheCredentialToWhatTheProofResolvedTo`, `testStatesTheConfirmedKeyInEveryFormat`. |
| 32 | A batch shares one format and Credential Dataset, with different cryptographic data (§3.3.2). | Met, untested in part | `CredentialIssuerCredentialController::issueCredential()`. The test compares the signed payloads of a `dc+sd-jwt` batch without mapped claims; that the disclosures (the user's claims) match, and the other formats, have no test. | `CredentialIssuerCredentialControllerTest::testTheCredentialsOfABatchDifferOnlyInWhatIdentifiesEach`. |
| 33 | Each key provided by the Wallet binds at most one credential (§8.3). | Gap (G13) | Proofs are validated one by one and a credential is issued for each, so a batch repeating a proof, or proving one key twice, gets several credentials bound to that key. | - |
| 34 | The issuer ignores unrecognized request parameters (§8.2). | Met, untested | The controller reads the parameters it knows. | - |
| 35 | Immediate issuance answers 200, `application/json`, with `credentials`, an array of objects each holding one `credential`; JWT and SD-JWT credentials are not re-encoded (§8.3, A.1.1.4, A.3.4). | Met, untested in part | `CredentialIssuerCredentialController::issueCredential()`. The unit tests mock the serialization and check the number of credentials and their payloads, not the status, the content type or the encoding. | `CredentialIssuerCredentialControllerTest`: `testCredentialWithMultipleProofs`, `testStatesTheConfirmedKeyInEveryFormat`. |
| 36 | A token which does not enable issuance gets an RFC 6750 section 3 error, with a `WWW-Authenticate` challenge (§8.3.1.1). | Partial (G14) | `CredentialIssuerCredentialController::credential()`, `invalidTokenResponse()`: `invalid_token` with its challenge. A token which does not grant the requested credential gets 403 `insufficient_scope` without a challenge, and one naming no user, or a user who no longer exists, gets 400 `invalid_request`. | `CredentialIssuerCredentialControllerTest`: `testAnswersWithInvalidTokenWhenTheAccessTokenIsNotFound`, `testAnswersWithInvalidTokenWhenTheAccessTokenIsRevoked`, `testAnswersARequestWithoutAnAccessTokenWithTheBareChallengeAlone`, `testRefusesAnAccessTokenNotIssuedForCredentialIssuance`, `testRefusesACredentialTheTokenDoesNotGrant` (status and code only). |
| 37 | Payload errors use the section 8.3.1.2 codes with 400 and `application/json` (§8.3.1.2). | Partial (G12) | `CredentialIssuerCredentialController::issueCredential()`; `OpenId4VciProofValidator` (`invalid_proof`, `invalid_nonce`). The fallback of row 28 answers with the pre-final `unsupported_credential_type`. The tests check the error code and the status, not the content type. | `CredentialIssuerCredentialControllerTest`: `testAnswersARefusedRequestWithTheErrorCodeTheRefusalCarried`, `testRefusesAnUnknownCredentialConfiguration`; `OpenId4VciProofValidatorTest::testAnswersAStaleNonceWithItsOwnErrorCode`. |
| 38 | `error_description` holds only characters in %x20-21 / %x23-5B / %x5D-7E (§8.3.1.2). | Gap (G2) | Descriptions quote names in `"` (%x22), and two of them repeat the requested format or credential identifier as the wallet sent it (`Routes::newJsonErrorResponse()` passes them through). | - |

## Metadata (§12)

| # | Requirement (spec ref) | Status | Enforced in | Covered by test |
|---|------------------------|--------|-------------|-----------------|
| 39 | The metadata is served at `/.well-known/openid-credential-issuer` inserted into the Credential Issuer Identifier, over TLS, with 200, unsigned `application/json` and a `Content-Type` (§12.2.2). | Met, untested in part; the location is Config | `CredentialIssuerConfigurationController::configuration()`, under the module's path. The well-known location of the identifier is published by the web server (see [docs/3](../docs/3-oidc-configuration.md), "Endpoint locations and well-known URLs"). The test checks the body, not the status or the content type. | `CredentialIssuerConfigurationControllerTest::testPublishesTheDocumentTheServiceBuilds`. |
| 40 | The response type matches the wallet's `Accept` header where supported (§12.2.2, RECOMMENDED). | Met, untested | `application/json` is the only type offered. | - |
| 41 | `credential_issuer` equals the identifier, an https URL without query or fragment (§12.2.1, §12.2.4, §4.1.1); `credential_endpoint` and `nonce_endpoint` use https (§12.2.4). | Met; the URL's form is Config | `CredentialIssuerMetadataService`: the identifier is the `issuer` option, checked only for being set, and the endpoints are the module's own URLs (SimpleSAMLphp's base URL). | `CredentialIssuerMetadataServiceTest::testPublishesTheIssuerAndItsEndpoints`. |
| 42 | `batch_credential_issuance.batch_size` is 2 or more, and states the cap enforced (§12.2.4; HAIP §4). | Met | `CredentialIssuerMetadataService` (`ModuleConfig::VCI_BATCH_SIZE`, 8; omitted when no configuration is proof bound); the cap: row 29. | `CredentialIssuerMetadataServiceTest`: `testPublishesTheBatchSizeItActuallyEnforces`, `testAProoflessConfigurationAdvertisesNoBindingAtAll`. |
| 43 | Issuer `display` (§12.2.4). | Met | `CredentialIssuerMetadataService::buildIssuerDisplay()`. | `CredentialIssuerMetadataServiceTest`: `testDescribesItselfToWalletsFromTheCommonMetadata`, `testLeavesOutWhatIsNotConfiguredFromItsDisplay`, `testPublishesNoDisplayWithNothingToDisplay`. |
| 44 | Each configuration's `scope`, `credential_signing_alg_values_supported` (IANA JOSE identifiers), and `cryptographic_binding_methods_supported` with `proof_types_supported` (both or neither) (§12.2.4, A.1.1.2, A.3.2, F.1). | Met | `CredentialIssuerMetadataService`: the active signing key's algorithm only; only the binding methods the issuer accepts. | `CredentialIssuerMetadataServiceTest`: `testDescribesWhatEachConfigurationCanBeProvedAndSignedWith`, `testAdvertisesTheAlgorithmOfTheActiveSigningKeyOnly`, `testAProoflessConfigurationAdvertisesNoBindingAtAll`, `testADiipConfigurationAdvertisesOnlyTheMethodsItAccepts`, `testAMethodTheRegistryCanNotResolveIsNotAdvertised`. |
| 45 | Each configuration's `format` is one the issuer supports, with the members its profile requires (`credential_definition.type` for `jwt_vc_json`, `vct` for `dc+sd-jwt`); `credential_metadata` `display` (one object per language) and `claims` (each `path` a non-empty claims path pointer; a `mandatory` claim always included) (§12.2.4, A.1.1.2, A.3.2, B.2). | Config (G7) | Published as written in `vci_credential_configurations_supported`: a configuration naming a format the issuer can not issue is advertised and fails at issuance. The module checks only the claim paths it maps attributes to (`ModuleConfig::getVciValidCredentialClaimPathsFor()`), and leaves out a claim advertised as `mandatory` when the user lacks its attribute. | `CredentialIssuerCredentialControllerTest::testSkipsAnAttributeMappedToAClaimPathTheConfigurationDoesNotAllow` (attribute mapping only). |
| 46 | When a configuration has no `scope`, the AS metadata lists `openid_credential` in `authorization_details_types_supported`, `authorization_details` being the only way to request it (§12.2.4). | Gap (G16) | `OpMetadataService` never publishes `authorization_details_types_supported`; and a configuration whose metadata has no `scope` can still be requested by the scope the module derives from its id (`ModuleConfig::getVciScopes()`). | - |
| 47 | The AS can tell from the metadata which claims a credential discloses, for meaningful consent (§12.2.4); consent is obtained, explaining what the credential contains and for what purpose (§15.1, SHOULD), and which client asks for which scopes (FAPI 2.0 §5.3.2.2, should). | Config (G8) | The AS and the issuer are one; the module renders no consent of its own, leaving it to SimpleSAMLphp authentication processing filters, which are given the client and the requested scopes, and the user's attributes rather than the credential's claims. | - |

## Security, implementation and privacy considerations (§13 to §15)

| # | Requirement (spec ref) | Status | Enforced in | Covered by test |
|---|------------------------|--------|-------------|-----------------|
| 48 | Follow the OAuth 2.0 Security BCP, and FAPI 2.0 where applicable (§5, §6, §13.2). | Partial | See the FAPI 2.0 section below. | - |
| 49 | DPoP is RECOMMENDED (§13.2). | Config | `DpopProofVerifier`, `BearerTokenValidator::ensureSenderConstraint()`; required for issuance with `vci_require_dpop` (default `false`), else per client (`dpop_bound_access_tokens`). | `DpopProofVerifierTest::testAcceptsAProofForTheRequestAndTheAccessToken`; `BearerTokenValidatorTest::testRefusesABoundTokenPresentedAsABearerToken`. |
| 50 | The AS states its client authentication requirements in `token_endpoint_auth_methods_supported` (§13.3). | Met | `OpMetadataService`. | `OpMetadataServiceTest::testItReturnsExpectedMetadata`. |
| 51 | Proof replay is limited with server-provided nonces (§13.8). | Partial (G21) | `OpenId4VciProofValidator`; `NonceService` (nonces expire), but see row 30. | `OpenId4VciProofValidatorTest::testAnswersAStaleNonceWithItsOwnErrorCode`; `NonceServiceTest::testValidateNonceExpired`. |
| 52 | Check how the Wallet protects its private keys, with the mechanisms of Appendix D (§13.8, RECOMMENDED). | Not implemented (H-G4) | No key attestations. | - |
| 53 | TLS per BCP 195, with server certificate checks (§13.9). | Config | The web server; outbound requests verify certificates unless `protocol_http_client_options` turns it off. | - |
| 54 | Long-lived access tokens are not issued unless sender-constrained (§13.10). | Met | `AuthCodeGrant::accessTokenTtlFor()`, used by both grants: an unbound issuance token lives at most `VCI_UNBOUND_ACCESS_TOKEN_MAX_TTL`. | `AuthCodeGrantTest::testChoosesTheAccessTokenLifetimeByTheCodesFlowAndBinding`; `PreAuthCodeGrantTest::testBindsTheTokenToTheProofsKeyAndGivesItTheLifetimeOfACredentialIssuanceToken`. |
| 55 | The Credential Endpoint serves repeated requests (§14.3), and does not revoke earlier credentials because of a later request (§14.3, SHOULD NOT). | Met; the second part untested | `CredentialIssuerCredentialController::issueCredential()`; nothing on that path revokes. | `CredentialIssuerCredentialControllerTest::testIssuesAgainstATokenWhichFollowedAnOfferForEveryRequestItMakes`. |
| 56 | Binding a DID issuer identifier to the Credential Issuer (§14.4, MAY). | Config | `VciDidDocumentController::didDocument()` publishes the document of a configured `did:web`; a `did:jwk` (`VciIssuerIdentityResolver`) is derived from the key and is not tied to the Credential Issuer's URL. Which identifier credentials carry is the deployment's choice. | `VciDidDocumentControllerTest::testPublishesTheDocumentForTheConfiguredDidWeb`. |
| 57 | Minimum disclosure: credentials meant for presentation use selective disclosure (§15.2). | Met | `CredentialIssuerCredentialController::issueCredential()`: every mapped attribute is a disclosure in the SD-JWT formats. | `CredentialIssuerCredentialControllerTest::testAddsEachMappedAttributeToTheDisclosureBag`. |
| 58 | Store as little End-User data as needed, logs included; do not keep issued credentials or the key material they are bound to (§15.3, §15.4.1). | Partial; Config (G20) | Issued credentials are not persisted; a status list entry keeps its index and a hashed subject reference (`SubjectRefHasher`). But the issuance log line (info) records the credential's `sub`, which for a key carried inline is a `did:jwk` of the holder's key, and the debug log records the whole request, proofs included: what is kept follows the log level. | - |
| 59 | Time claims are randomized or rounded to resist correlation (§15.4.1). | Config | `vci_time_claim_granularity` (default `P1D`; `PT0S` turns rounding off), applied by `CredentialIssuerCredentialController::issueCredential()`. | `CredentialIssuerCredentialControllerTest`: `testStatesTheIssuanceRoundedDownToTheGranularity`, `testStatesTheExpiryRoundedUpFromTheMomentOfIssuance`. |

## Credential formats, claims and proofs (Appendices A, C, F)

| # | Requirement (spec ref) | Status | Enforced in | Covered by test |
|---|------------------------|--------|-------------|-----------------|
| 60 | `jwt_vc_json`: no JSON-LD processing; the credential is a JWT (A.1.1). | Met, untested in part | `CredentialIssuerCredentialController::issueCredential()`; the tests mock the serialization (row 35). | `CredentialIssuerCredentialControllerTest::testCredentialWithMultipleProofs`. |
| 61 | `dc+sd-jwt`: the credential is an SD-JWT VC string whose `vct` is the configuration's (A.3.2, A.3.4), a collision-resistant name (SD-JWT VC draft 11 §3.2.2.1). | Partial (G15) | `CredentialIssuerCredentialController::issueCredential()` writes the configuration id as `vct`, whatever `vct` the configuration advertises; whether that is a collision-resistant name is the configuration's. | `CredentialIssuerCredentialControllerTest::testResolvesTheConfigurationFromTheVct` (an id equal to its `vct`; no test has them differ). |
| 62 | A claims path pointer is a non-empty array of strings, nulls and integers (C). | Partial (G7) | The openid library's `ClaimsPathPointerResolver` refuses other components but resolves an empty path to the root; the module checks configured paths only where it maps attributes (row 45). | The library's `ClaimsPathPointerResolverTest::testThrowsForInvalidPathComponent`. |
| 63 | `jwt` proof header: `alg` asymmetric and advertised, `typ` `openid4vci-proof+jwt`, exactly one of `kid`, `jwk`, `x5c` (F.1). | Partial (G17); `typ` untested | `OpenId4VciProofValidator` and the openid library's `OpenId4VciProof` (`typ`); `x5c` is refused as unsupported, a `kid` must be a DID URL naming a verification method, a `jwk` must be public. A member set to `null` counts as absent, so `kid: null` and `x5c: null` next to a `jwk` pass. The module's tests mock the parsed proof, so the `typ` check has no test. | `OpenId4VciProofValidatorTest`: `testRefusesASymmetricInlineKey`, `testRefusesAnUnadvertisedSigningAlgorithm`, `testRefusesAHeaderNamingMoreThanOneKeySource`, `testRefusesAKeyIdWhichNamesOnlyTheDid`, `testRefusesACertificateChainHeader`, `testRefusesPrivateKeyMaterialInAnInlineKey`. |
| 64 | The `key_attestation` and `trust_chain` headers, when present, are validated, their `alg` among those advertised (F.1). | Gap (G17) | Neither is read: an otherwise valid proof carrying one passes. | - |
| 65 | `jwt` proof claims: `iss` is the client's `client_id`, omitted for anonymous pre-authorized access; `aud` the issuer, as a string; `iat`; `nonce` (F.1). | Partial (G17) | `OpenId4VciProofValidator`; `iat` in the openid library's `OpenId4VciProof`, untested. An `aud` written as a one-element array naming the issuer is accepted, and an `iss` set to `null` passes as omitted. | `OpenId4VciProofValidatorTest`: `testRefusesAnIssuerClaimNamingAnotherClient`, `testRefusesAnIssuerClaimWhenTheAccessTokenIdentifiesNoClient`, `testRefusesAnAudienceWhichDoesNotNameThisIssuer`, `testRefusesAProofCarryingNoNonce`, `testAcceptsASingleAudienceWrittenAsAnArray` (pins the leniency). |
| 66 | The proof is signed by the key its header identifies (F.1, F.4). | Met, untested in part | `OpenId4VciProofValidator` verifies with the key it resolved from the header; the tests do not pin which key the verification used. | `OpenId4VciProofValidatorTest`: `testRefusesAProofWhoseSignatureDoesNotVerify`, `testAcceptsAValidProof`. |

## Not implemented (optional features)

None of these is advertised in the metadata, unless an administrator configures a credential in one of the
formats below (row 45). A request using one anyway is refused, except where noted.

- **Credential Offer by reference** (§4.1.3), and offers sent to a wallet's `credential_offer_endpoint`
  (§12.1).
- **Deferred issuance** (§8.3 `transaction_id`, §9) and the **Notification Endpoint** (§8.3 `notification_id`,
  §11).
- **Encrypted Credential Requests and Responses** (§8.2, §10, `credential_request_encryption`,
  `credential_response_encryption`). A request asking for an encrypted response is answered in plain JSON.
- **DPoP nonces** from the Nonce Endpoint or elsewhere (§7.2, RFC 9449 section 8). A `nonce` claim in a DPoP
  proof is not checked.
- **Signed Credential Issuer Metadata** (§12.2.3), language negotiation of the metadata (§12.2.2), and
  `authorization_servers` (§12.2.4): the OP is the only Authorization Server.
- **Credential formats** `ldp_vc`, `jwt_vc_json-ld` and `mso_mdoc` (A.1.2, A.1.3, A.2).
- **Proof types** `di_vp` and `attestation`, and the `x5c` header of `jwt` proofs (F.1-F.3); **key
  attestations** (Appendix D, `key_attestations_required`). The `key_attestation` and `trust_chain` headers
  are ignored (row 64).
- **Wallet Attestations** (Appendix E) as a client authentication method.

## HAIP 1.0 (issuer)

| # | Requirement (HAIP ref) | Status | Notes |
|---|------------------------|--------|-------|
| 67 | Support the authorization code flow (§4). | Met | `AuthCodeGrantTest::testSpendsTheIssuerStateOfACredentialOfferCodeAndCarriesItOntoTheToken`. |
| 68 | Support the IETF SD-JWT VC profile of §6 (§3, §4). | Partial | `dc+sd-jwt` is issued; the §6.1 requirements below are not all met. |
| 69 | Comply with the applicable FAPI 2.0 provisions: PKCE with S256, PAR where the authorization endpoint is used, `iss` in the authorization response (§4). | Partial | See the FAPI 2.0 section. |
| 70 | Support DPoP (§4). | Met; Config | Required for issuance with `vci_require_dpop` (default `false`). |
| 71 | Issuer-initiated flows use the Credential Offer, same-device and cross-device (§4, §4.2). | Met | The offer API returns the offer URI; presenting it as a link or a QR code is the caller's (but see O1). `VciCredentialOfferApiControllerTest::testBuildsAnOfferForTheAuthorizationCodeFlow`. |
| 72 | Batch issuance support is stated by including or omitting `batch_credential_issuance` (§4). | Met | Row 42. |
| 73 | AS metadata per RFC 8414; issuer metadata per OpenID4VCI §12.2.2 (§4.1). | Met | `OAuth2ServerConfigurationControllerTest::testItServesTheOpMetadataAsIs`; row 39. |
| 74 | A `scope` for every Credential Configuration (§4.1); for the authorization code grant, a scope value lets the wallet identify the credential (§4.2). | Config (H-G9) | `scope` is optional in `vci_credential_configurations_supported` (when present it must equal the configuration id). OpenID4VCI 1.0 offers have no `scope` member, so the wallet takes it from the metadata. |
| 75 | `nonce_endpoint` is present when a configuration requires key binding (§4.1). | Met | Row 25. |
| 76 | Wallets authenticate at the PAR endpoint as at the token endpoint (§4.3). | Gap (H-G1) | The PAR endpoint authenticates clients as the token endpoint does, but public clients and non-registered wallets push unauthenticated (row 78). |
| 77 | Refresh tokens are RECOMMENDED for credential refresh; consider how long they may refresh a credential (§4.4). | Gap (G18) | The authorization code grant issues a refresh token in an issuance flow which asks for `offline_access`, but the access token a refresh yields does not keep the issuance flow, so the Credential Endpoint refuses it; the pre-authorized code grant issues none. |
| 78 | Issuers MUST require client authentication at the PAR and token endpoints (§4.4.1). | Gap (H-G1) | Public clients, non-registered wallets and anonymous pre-authorized code requests are served without client authentication; Wallet Attestation (OpenID4VCI Appendix E, attestation-based client authentication) is not implemented. |
| 79 | Key attestations, with `x5c` chains excluding the trust anchor, not self-signed (§4.5.1). | Not implemented (H-G4) | Wallets MUST support them; issuers evaluate them where the ecosystem requires. |
| 80 | Compact serialization of SD-JWT VCs (§6.1). | Met, untested | The tests mock the serialization (row 35). |
| 81 | It is RECOMMENDED to limit the validity of SD-JWT VCs, and a limited one uses `exp`, `status` or both (§6.1). | Config | Credential lifetimes per configuration (`vci_credential_ttls`, none by default); status lists when enabled (off by default). | 
| 82 | `cnf` as in SD-JWT VC, with the key in `jwk` when the configuration requires holder binding (§6.1). | Partial (H-G3) | `cnf.jwk` for proofs carrying a `jwk`; `cnf.kid` for proofs naming a DID verification method. `CredentialIssuerCredentialControllerTest::testAKeyBoundSdJwtVcNamesItsHolderByCnfAlone`. |
| 83 | `status` contains `status_list`; every credential has its own unique, unpredictable index (§6.1). | Met; unpredictability untested | `DbStatusIndexAllocator` picks free indices at random. `DbStatusIndexAllocatorTest::testNeverHandsOutTheSameIndexTwice` (uniqueness); `CredentialIssuerCredentialControllerTest::testMergesTheStatusClaimIntoTheCredential`. |
| 84 | Status List Tokens carry the signing certificate in `x5c`, without the trust anchor, not self-signed (§6.1). | Gap (H-G2) | `DbStatusListTokenProvider` signs with a `kid` (`did:jwk`, `did:web` or the JWKS); no `x5c`. |
| 85 | SD-JWT VCs carry the issuer's signing certificate and chain in `x5c`, without the trust anchor, not self-signed; X.509 key resolution (§6.1.1). | Gap (H-G2) | Credentials name their key with a `kid`; no X.509 support. |
| 86 | ES256 and SHA-256 are supported (§7, §8). | Met | ES256 proofs and signing keys; SHA-256 disclosure digests. `CredentialIssuerCredentialControllerTest::testSignsEveryCredentialWithTheActiveSigningKey` (signing); the library's `SdJwtFactoryTest::testCanUpdatePayloadWithDisclosures`. ES256 proof verification is untested (the proof tests mock it). |
| 87 | Signed issuer metadata where an ecosystem requires it, with `x5c` (§4.1); the `haip-vci://` scheme (§4.2, MAY). | Not implemented | |

## FAPI 2.0 Security Profile (as applied by HAIP §4)

HAIP §4 takes FAPI 2.0 client authentication out, requiring client authentication of its own (§4.4.1, row
78) for which Wallet Attestation can be used, requires PAR only where
the authorization endpoint is used, and replaces the algorithm list of §5.4.1 clause 1 with its own §7. The
rows on confidential clients only, client authentication methods and the `aud` of client assertions
(§5.3.2.1, §5.3.3.1) therefore do not apply.

| # | Requirement (FAPI 2.0 ref) | Status | Notes |
|---|----------------------------|--------|-------|
| 88 | TLS 1.2 or later per BCP 195, only the BCP 195 cipher suites for TLS 1.2, certificate checks, no TLS stripping; DNSSEC (should) (§5.2). | Config | The web server and the DNS. |
| 89 | No CORS at the authorization endpoint (§5.2.3). | Gap (H-G7) | `AuthorizationController` adds `Access-Control-Allow-Origin: *` to the responses it builds normally (not to error responses). |
| 90 | Discovery metadata; no resource owner password credentials grant (§5.3.2.1). | Met; the refusal untested | `OpMetadataServiceTest::testItReturnsExpectedMetadata` (the advertised grants); the password grant is never registered (`AuthorizationServerFactory`). |
| 91 | No open redirectors (§5.3.2.1). | Partial; Config (G22) | `ClientRedirectUriRule` matches the registered redirect URIs exactly. With `vci_allow_non_registered_clients`, a credential request carrying `issuer_state` whose redirect URI does not match is accepted when it starts with one of `vci_allowed_redirect_uri_prefixes_for_non_registered_clients` (default `openid-credential-offer://`), and that fallback applies to registered clients too. `ClientRedirectUriRuleTest::testMatchesTheRegisteredListExactlyRatherThanByPrefix` (fallback off). |
| 92 | Only sender-constrained access tokens, by DPoP or MTLS (§5.3.2.1). | Config (H-G10) | `vci_require_dpop` (default `false`). MTLS is not implemented. |
| 93 | Authorization codes live at most 60 seconds (§5.3.2.1). | Config (H-G10) | `authCodeDuration`, default `PT10M`. |
| 94 | Authorization code binding to the DPoP key (§5.3.2.1). | Met | `dpop_jkt`. `AuthCodeGrantTest`: `testRedeemsACodeBoundToAKeyWithAProofByThatKey`, `testRefusesACodeBoundToAKeyWithoutAProofByThatKey`. |
| 95 | Accept JWTs with an `iat` or `nbf` up to 10 seconds ahead, refuse more than 60 (§5.3.2.1). | Met for DPoP proofs; Config otherwise | `DpopProofVerifierTest::testHoldsTheIssuedAtToAMinuteEitherWay`; the library's `ParsedJwsTest::testHoldsNotBeforeAndIssuedAtAgainstTheClockWithTheirFractions`. Other JWTs are held to `timestamp_validation_leeway` (default one minute), which has to stay between 10 and 60 seconds. |
| 96 | Access token privileges are the minimum needed (§5.3.2.1, should). | Config | Per client: the scopes it may have. |
| 97 | No refresh token rotation except in extraordinary circumstances, and then with a retry window (§5.3.2.1). | Gap (H-G6) | `RefreshTokenGrant` rotates the refresh token on every use and revokes the old one at once. |
| 98 | `response_type` `code` only (§5.3.2.2). | Config | Per client (`response_types`) and `enabled_grant_types`. |
| 99 | Client-authenticated PAR; authorization requests without PAR are refused (§5.3.2.2). | Partial; Config (H-G1, H-G10) | PAR is required with `require_pushed_authorization_requests` (default `false`); public clients push unauthenticated (row 78). |
| 100 | PKCE with S256 required (§5.3.2.2). | Gap (H-G5) | `plain` is accepted and advertised (`code_challenge_methods_supported`), and PKCE is optional for confidential clients. |
| 101 | `redirect_uri` required in PAR; `iss` in the authorization response; a used code is refused (§5.3.2.2). | Met | `ClientRedirectUriRuleTest::testRejectsARequestWithoutARedirectUri`; `AuthCodeGrantTest::testNamesItselfAsTheIssuerInTheAuthorizationResponse`, `testRevokesRelatedTokensWhenAuthorizationCodeIsReplayed`. |
| 102 | No `http` redirect URIs except native loopback (§5.3.2.2). | Gap (H-G8) | `ClientMetadataValidator` holds web clients to https only when they use the implicit grant. |
| 103 | No HTTP 307 for redirects; 303 SHOULD be used (§5.3.2.2). | Partial (H-G11) | Redirects use 302. |
| 104 | PAR `expires_in` less than 600 seconds (§5.3.2.2). | Config (H-G10) | `par_request_uri_ttl`, default `PT10M`, which is 600 seconds exactly. |
| 105 | With OpenID Connect, `nonce` values up to 64 characters are supported (§5.3.2.2), and the user's identifier reaches the client in an ID Token (§5.3.2.3). | Met; the nonce length untested | The nonce is not length-limited. `TokenResponseTest::testCarriesBothTheIdTokenAndTheAuthorizationDetailsWhenTheVciFlowRequestedOpenid`. |
| 106 | Resource server: tokens in the header, never in the query; validity, expiry, revocation, sufficiency and sender constraint checked (§5.3.4). | Met, untested in part; see G14 | `BearerTokenValidatorTest`: `testValidatesForAuthorizationHeader`, `testRefusesARevokedAccessTokenAsAnInvalidToken`, `testAcceptsATokenUnderTheDpopSchemeWithAProofByTheKeyItIsBoundTo`, `testRefusesABoundTokenPresentedAsABearerToken`. The query refusal and the expiry check have no test of their own here; an insufficient token lacks its challenge (row 36). |
| 107 | RSA keys of at least 2048 bits; EC keys of at least 224 bits (§5.4.1). | Partial (H-G11) | The openid library refuses a shorter RSA key in a DPoP proof; other RSA keys (clients', the OP's own) are not checked. The supported curves are all 256 bits or more. |
| 108 | Secrets with at least 128 bits of entropy (§5.4.1). | Met, untested; Config | What the module generates (`Helpers\Random`) draws from a CSPRNG; `RandomTest::testCanGetIdentifier` checks only that a value comes back. A client secret an administrator types in is checked for its characters and length only. |
| 109 | `jwks_uri` over TLS, no `x5u` or `jku`, no repeated `kid`; a verifier facing a repeated `kid` tries the keys by their other attributes (§5.4.2, §5.4.3). | Met, untested; Config | The module never sets `x5u` or `jku`; key sets are verified through web-token's `JWSVerifier`, which tries each candidate key. TLS and distinct key ids are the deployment's. |
| 110 | Certified implementations; key rotation, single-purpose keys, stateful credentials where they help, credentials of one authorization linked (§6.6, §6.8, should); client ids which can not pass for an End-User's (§6.7, should). | Config; Met, untested | Keys are rolled over by configuration. Access tokens are checked against their stored state, and the tokens of one authorization code are linked (a replayed code revokes them). Registration generates the client ids it issues. |

## Gaps

OpenID4VCI 1.0 (the base specification):

- **G1** Unknown scope values are refused with `invalid_scope` instead of being ignored (row 12). OpenID Connect
  Core also says unknown scope values SHOULD be ignored; RFC 6749 allows the refusal.
- **G2** `error_description` values hold `"` and echo request values (row 38).
- **G3** The `tx_code` description can exceed 300 characters, and carries the user's e-mail address into the
  offer (rows 6, 8).
- **G4** `pre-authorized_grant_anonymous_access_supported` is not published, though anonymous access is
  accepted (row 19).
- **G5** `claims` in authorization details are neither validated nor honoured, and are returned in the token
  response as if granted (row 11).
- **G6** The authorization code grant ignores `authorization_details` in the token request: no narrowing
  (RECOMMENDED), and no `authorization_details` in the response for a code authorized by scope (MUST) (row 22).
- **G7** Credential configurations are published as configured: an unsupported `format`, a missing
  `credential_definition.type` or `vct`, repeated display languages and malformed claim paths go out
  unchecked, and a claim advertised as `mandatory` is left out when the user lacks its attribute (rows 45, 62).
- **G8** No consent screen of the module's own shows what a credential will contain and why (row 47).
- **G9** Authorization details: an unknown `credential_configuration_id` passes when there is no
  `issuer_state`; a malformed value is dropped silently; a refused detail gets a bare 400 `invalid_request`,
  not redirected, rather than `invalid_authorization_details` (rows 9, 16).
- **G10** A credential requested by scope next to authorization details for another one can not be fetched
  (row 10).
- **G11** The token response returns authorization details for configurations the grant dropped (row 23).
- **G12** A Credential Request naming neither `credential_identifier` nor `credential_configuration_id` is
  served by the pre-final format and type resolution, which answers an unknown format with the pre-final
  `unsupported_credential_type`; one naming both passes when either is `null` (rows 28, 37).
- **G13** One key can be bound to several credentials of a batch (row 33).
- **G14** A token which does not grant the credential gets 403 `insufficient_scope` without a
  `WWW-Authenticate` challenge; one whose user is missing gets 400 `invalid_request` (row 36).
- **G15** The issued `vct` is the configuration id, not the configuration's `vct`, and nothing checks it is a
  collision-resistant name (row 61).
- **G16** `authorization_details_types_supported` is never published, and a configuration without a metadata
  `scope` can still be requested by scope (row 46).
- **G17** Key proofs: `key_attestation` and `trust_chain` headers are ignored; `null` members count as
  absent; an `aud` written as a one-element array is accepted (rows 63 to 65).
- **G18** Refresh tokens issued in issuance flows yield access tokens the Credential Endpoint refuses (row 77).
- **G19** Offers do not refuse a repeated configuration id, and the factory does not check offers for the
  authorization code flow for unsupported ids (row 2).
- **G20** The issuance log keeps the holder's key (as the credential's `sub`) at info level, and the whole
  request at debug level (row 58).
- **G21** A `c_nonce` is told from other JWS this issuer signs by nothing but its claims' presence: an
  unexpired credential passes as a nonce (rows 30, 51).
- **G22** The redirect URI prefixes allowed for non-registered wallets also let a registered client's
  credential request use a redirect URI it never registered (row 91).
- **G23** Token errors: `invalid_request` where RFC 6749 names `invalid_grant`, `access_denied` where it names
  `invalid_client`; a narrowed `scope` is not stated in the response (row 20).

Observed outside the requirement rows:

- **O1** The admin test page for credential issuance renders the offer's QR code through quickchart.io: the
  browser sends the whole offer URI there, with its pre-authorized code and, when a Transaction Code is used,
  the user's e-mail address in the `tx_code` description. A pre-authorized code without a Transaction Code can
  be redeemed by anyone who reads it before it expires.

HAIP 1.0 and the FAPI 2.0 provisions it applies:

- **H-G1** Client authentication is not required at the PAR and token endpoints; no Wallet Attestation
  (rows 76, 78, 99).
- **H-G2** No `x5c` (X.509) issuer keys for SD-JWT VCs and Status List Tokens (rows 84, 85).
- **H-G3** `cnf.kid` instead of `cnf.jwk` for DID-bound keys (row 82).
- **H-G4** No key attestations (rows 52, 79).
- **H-G5** PKCE `plain` accepted; PKCE optional for confidential clients (row 100).
- **H-G6** Refresh tokens rotate on every use (row 97).
- **H-G7** CORS at the authorization endpoint (row 89).
- **H-G8** `http` redirect URIs allowed for code flow web clients (row 102).
- **H-G9** `scope` optional per Credential Configuration (row 74).
- **H-G10** Defaults outside FAPI 2.0: codes live 10 minutes, PAR not required, PAR URIs live 600 seconds,
  DPoP not required (rows 92, 93, 99, 104).
- **H-G11** 302 redirects; RSA key length checked only in DPoP proofs (rows 103, 107).
