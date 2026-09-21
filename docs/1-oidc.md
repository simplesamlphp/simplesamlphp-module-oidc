# OIDC Module

This module adds support for the OpenID Provider (OP) role from the
OpenID Connect protocol to SimpleSAMLphp. It is installable via Composer
and is based on the
[OAuth2 Server from the PHP League](https://oauth2.thephpleague.com/).

Supported flows:

- Authorization Code, with PKCE (response_type: `code`)
- Implicit (response_type: `id_token token` or `id_token`)
- Refresh Token

All three are enabled by default. The Implicit and Refresh Token flows can be
switched off with the `enabled_grant_types` option, which takes them out of the
discovery metadata, out of client registration and off the authorization
server alike (the `offline_access` scope goes with the Refresh Token flow); see
[Configuration](3-oidc-configuration.md#enabled-grant-types-flows). OAuth 2.0
Security Best Current Practice (RFC 9700) advises against the implicit grant,
so a deployment with no client depending on it should disable it.

Authorization request parameters can be sent as plain parameters, by value as a
Request Object (`request`, OpenID Connect Core / JAR), or by reference
(`request_uri`) — either via Pushed Authorization Requests (PAR, RFC 9126) or a
remote `https://` Request Object. See
[Configuration](3-oidc-configuration.md#pushed-authorization-requests-par-and-request-objects)
for details.

## Supported specifications

This OP implements (or, where noted, partially implements) the following
specifications:

OpenID Connect:

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
  — Authorization Code and Implicit flows, ID Token, UserInfo, and the `request`
  object (passed by value and by reference)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
  — `/.well-known/openid-configuration`
- [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
  — the Client Registration Endpoint (`registration_endpoint`); disabled by
  default. See the [DCR note](#note-on-dynamic-client-registration-dcr) below
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
  — supported response modes are `query`, `fragment`, and `form_post`

OAuth 2.0:

- [The OAuth 2.0 Authorization Framework (RFC 6749)](https://www.rfc-editor.org/rfc/rfc6749)
  and [Bearer Token Usage (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750)
- [Proof Key for Code Exchange, PKCE (RFC 7636)](https://www.rfc-editor.org/rfc/rfc7636)
- [OAuth 2.0 Authorization Server Metadata (RFC 8414)](https://www.rfc-editor.org/rfc/rfc8414)
  — `/.well-known/oauth-authorization-server`
- [JWT Profile for Client Authentication (RFC 7523)](https://www.rfc-editor.org/rfc/rfc7523)
  — `private_key_jwt` at the token, PAR and token introspection endpoints
  (the token and introspection endpoints also support `client_secret_basic`
  and `client_secret_post`)
- [OAuth 2.0 Token Introspection (RFC 7662)](https://www.rfc-editor.org/rfc/rfc7662)
  — optional endpoint, advertised as `introspection_endpoint` while enabled
- [JWT Profile for OAuth 2.0 Access Tokens (RFC 9068)](https://www.rfc-editor.org/rfc/rfc9068)
  — the access token JWT has the profile's shape (`typ: at+jwt`, `client_id`,
  `scope`); `aud` remains the client identifier, as resource indicators
  (RFC 8707) are not implemented
- [JWT-Secured Authorization Request, JAR (RFC 9101)](https://www.rfc-editor.org/rfc/rfc9101)
  — `request` and `request_uri`
- [OAuth 2.0 Pushed Authorization Requests, PAR (RFC 9126)](https://www.rfc-editor.org/rfc/rfc9126)
- [OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)](https://www.rfc-editor.org/rfc/rfc7591)
  and [OAuth 2.0 Dynamic Client Registration Management Protocol (RFC 7592)](https://www.rfc-editor.org/rfc/rfc7592)
  — client register / read / update / delete at the `registration_endpoint`;
  disabled by default. See the [DCR note](#note-on-dynamic-client-registration-dcr) below

Drafts / experimental (see the notes below for scope and caveats):

- OpenID Federation — automatic client registration and related features
- OpenID for Verifiable Credential Issuance, OpenID4VCI (experimental,
  not for production)
- [Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
  — what makes an issued credential revocable and suspendable; off by default.
  See [Configuration](3-oidc-configuration.md#token-status-lists-credential-revocation)
- [Decentralized Identity Interop Profile, DIIP v5](https://FIDEScommunity.github.io/DIIP)
  — the **Issuer Agent** role only. See the [DIIP note](#note-on-the-diip-profile)
  below

## Note on Dynamic Client Registration (DCR)

The OP can let clients register themselves at the Client Registration Endpoint
(`registration_endpoint`, served at `<basepath>/module.php/oidc/register`),
implementing OpenID Connect Dynamic Client Registration 1.0 / RFC 7591 (create,
read) and RFC 7592 (update, delete via the Client Configuration Endpoint,
authenticated with the Registration Access Token issued at registration).

DCR is **disabled by default**. When disabled, the registration endpoint returns
`404` and is not advertised in discovery. When enabled, registration can be open
or gated by an Initial Access Token, and impersonation protection
(`logo_uri`/`policy_uri`/`tos_uri` host matching) is on by default.

Most standard client metadata is supported. Metadata for features this OP does
not implement is **rejected** with `invalid_client_metadata` rather than silently
ignored — namely `subject_type` other than `public`, `sector_identifier_uri`,
signed/encrypted UserInfo, ID Token / Request Object encryption, and front-channel
logout. The full per-field policy (honored / validated / rejected) is documented in
[DCR client metadata support](9-oidc-dcr-client-metadata.md). See the
[upgrade guide](6-oidc-upgrade.md#version-6-to-7) for the configuration options,
the client properties involved, and guidance for existing clients.

## Note on OpenID Federation (OIDFed)

OpenID Federation support is in draft phase. You can
expect breaking changes in future releases related to OIDFed
capabilities. OIDFed can be enabled or disabled in the module
configuration.

Currently supported OIDFed features:

- Automatic client registration using a Request Object
- Federation participation limiting based on Trust Marks
- Endpoint for issuing a configuration entity statement (about itself)
- The OpenID4VCI issuer metadata and the credential signing keys published in
  that entity statement under the `openid_credential_issuer` and `vc_issuer`
  entity types, and issued credentials naming this entity for trust
  establishment — all per the OpenID Federation Digital Credentials Profile,
  see [Note on the DIIP profile](#note-on-the-diip-profile)

The OP participates as a leaf entity, so it deliberately does not serve a fetch
endpoint or a subordinate listing endpoint.

OIDFed is implemented using the
[SimpleSAMLphp OpenID library](https://github.com/simplesamlphp/openid).

## Note on OpenID for Verifiable Credential Issuance (OpenID4VCI) support

OpenID4VCI support is experimental. You should NOT use it in production
environments.

The implementation follows OpenID4VCI, but it has not been reviewed against the
final 1.0 specification as a whole: parts of it were written against earlier
drafts and have since been corrected towards 1.0, one piece at a time. No
specific specification version is claimed here, and no interoperability with 1.0
wallets is promised. A full review against 1.0 is planned; it may change the wire
format incompatibly, so credentials and Status List Tokens issued by this version
may stop verifying, and a future release may require re-issuing them.

Currently implemented OpenID4VCI features:

- Implemented Endpoints
  - Credential Issuer Metadata | `.well-known/openid-credential-issuer` -
  Advertises supported credentials, algorithms, and endpoints.
  - Credential Endpoint | `credential-issuer/credential` - Handles credential
  requests with proof of possession.
  - Nonce Endpoint | `credential-issuer/nonce` - Provides nonces (`c_nonce`).
  - Credential Offer (API) | `api/vci/credential-offer` - Allows triggering
  credential offers via administrative API.
  - Credential Status (API) | `api/vci/credential-status` - Withdraws, suspends
  or reinstates an issued credential through its Token Status List entry.
  - JSON-LD Context | `credential-issuer/context/{credentialConfigurationId}` -
  Serves custom JSON-LD contexts for `vc+sd-jwt` credentials.
  - Status List | `statuslist/{statusListId}` - Serves the signed Token Status
  List that an issued credential's `status` claim points at.
  - DID Document | `did.json` - Serves this issuer's `did:web` document, so a
  verifier can resolve the key a credential was signed with. Served whenever a
  `did:web` identifier is configured — but at the module's own URL, so the URL
  that identifier resolves to still has to be routed here by the web server.
  See [Configuration](3-oidc-configuration.md#serving-the-did-document).
  - JWT VC Issuer Metadata | `.well-known/jwt-vc-issuer` - Points an SD-JWT VC
  verifier at this issuer's key set.
- Supported Flows & Grant Types
  - Authorization Code Flow: Fully supported
  - Pre-Authorized Code Flow: Fully supported. Client authentication at the
  token endpoint is optional, as OpenID4VCI 1.0 (section 6.1) has it. A wallet
  may authenticate with any supported method (`private_key_jwt`,
  `client_secret_basic`, `client_secret_post`), in which case it has to be a
  registered client, and credentials which do not verify are refused with
  `invalid_client`; it may identify itself with a bare `client_id`, which a
  non-registered wallet is taken at its word for; or it may send neither and
  redeem the code anonymously. A registered wallet gets the access token issued
  to itself (its `client_id` is the token's audience); a non-registered or
  anonymous wallet gets a token issued to the generic VCI client. Whatever
  identified the wallet is what the `iss` claim of its key proof is checked
  against at the credential endpoint, and an anonymous wallet has to omit that
  claim.
  - Authorization Details: Support for `openid_credential` type in authorization
  and token requests.
- Supported Credential Formats
  - JWT VC JSON (`jwt_vc_json`): W3C VCDM v1.1 Verifiable Credentials encoded as
  JWT.
  - Selective Disclosure JWT (`vc+sd-jwt`): W3C VCDM 2.0 based Selective
  Disclosure JWT.
  - Digital Credentials SD-JWT (`dc+sd-jwt`): IETF Draft 14+ Selective
  Disclosure JWT.
- Proof of Possession & Binding
  - Proof Type: `jwt` (JSON Web Token proofs).
  - Cryptographic Binding Methods:
    - `did:key`: Supported for proof validation and subject binding.
    - `did:jwk`: Supported for proof validation and subject binding.
    - `did:web`: Supported for proof validation and subject binding. The
    document is fetched over the network, so DID resolution has a destination
    policy of its own, separate from the federation one.
    - A key proof may also carry its key inline in a `jwk` header. That is a
    documented extension rather than a profile feature.
  - Nonce Validation for mandatory `c_nonce` validation in proofs.
  - Holder binding is stated in a `cnf` claim, in every credential format.
  - Each credential configuration decides for itself whether a key proof is
  required and which identifier rules apply to it. See
  [Configuration](3-oidc-configuration.md#holder-binding-and-the-diip-profile).
- Issuer Identity: a `did:jwk` derived from the signing key (default), a
configured `did:web` whose document this module publishes, or the issuer URL
with the key resolved through the published key set. See
[Configuration](3-oidc-configuration.md#issuer-identity-and-the-did-document).
- Credential Status: a Token Status List entry allocated at issuance, and
withdraw / suspend / reinstate through the admin UI or the API. See
[Configuration](3-oidc-configuration.md#token-status-lists-credential-revocation).
- JSON-LD Support: Ability to host and reference custom JSON-LD contexts for
enhanced semantic interoperability
- API for credential offer fetching

OpenID4VCI is also implemented using the
[SimpleSAMLphp OpenID library](https://github.com/simplesamlphp/openid).

## Note on the DIIP profile

The [Decentralized Identity Interop Profile (DIIP)](https://FIDEScommunity.github.io/DIIP),
release v5, sits on top of OpenID4VCI and names three roles: Issuer, Holder and
Verifier. This module implements the **Issuer Agent** role, and what is claimed
here is scoped to that role rather than to "DIIP conformance" unqualified:

- **Issuer — in scope.** The module can be identified by a `did:jwk` or a
  `did:web`, and publishes a DID document for the latter. A Status List Token is
  signed under an identity of its own, chosen by the pool's key profile rather
  than by the credential issuer mode — so having a credential and the status
  token it points at name the same `did:web` means setting both. See [Key
  profile](3-oidc-configuration.md#key-profile).
- **Holder — in scope, as a consumer of holder identifiers.** The module holds
  no credentials of its own, but it accepts a holder's `did:jwk` or `did:web` in
  an OpenID4VCI key proof, verifies the proof against the key that DID resolves
  to, and binds the issued credential to it.
- **Verifier — out of scope.** There is no OpenID4VP surface here at all: no
  `vp_token`, no `presentation_definition`, no request object endpoint for
  presentation. The profile's `did` Client Identifier Scheme requirement belongs
  to that surface, so it does not apply to this module. If OpenID4VP
  verification is ever added, verifier identifiers come back into scope and
  nothing below covers them.

**Nothing certifies this, and it is not a claim about the whole profile.** There
is no DIIP conformance suite of the kind the OpenID Foundation runs for OpenID
Connect (see [Conformance testing](#conformance-testing) below for what is
actually tested), so this is a self-assessment. Every requirement of the v5
text which addresses the Issuer has been traced against the source, one at a
time: the identifier half first — that Issuers and Holders can be identified by
`did:jwk` and `did:web`, and the two identifier-dependent issuance
requirements, the `jwt` proof type and the `cnf` holder binding claim — and
then the rest of the profile, the credential formats, the signature algorithm,
the issuance flows, revocation, and the optional Trust Establishment appendix.
Two readings this module makes along the way — what the profile's `iss`
requirement can mean alongside OpenID4VCI, and which party's DID document its
`assertionMethod` sentence is about — are written out under [Three
interpretations this module makes](3-oidc-configuration.md#three-interpretations-this-module-makes),
so a deployment which reads them differently knows where it differs.

Only one of those rules is a **per credential configuration** choice, and it is
the one about the *holder's* identifier: the `DiipProofBound` binding policy
requires the key proof to name its key in a `kid` header which is an absolute
`did:jwk` or `did:web` URL, so inline keys and `did:key` holders are refused. It
applies to the configurations that ask for it and to no others, because DIIP's
requirements are additive. The rest are not per configuration at all — the
*issuer's* identity is deployment wide, and a `cnf` claim is emitted by every
proof-bound configuration rather than only by the DIIP ones.

**Choosing that policy is therefore not by itself a conformant deployment**, and
neither is any single setting. The profile also places requirements on the
deployment as a whole — credential formats, signature algorithm, the issuance
flows, revocation — and the capabilities are there, but several are switched
on by configuration rather than present by default. The
one most easily missed is a setting rather than a feature: DIIP requires the
Issuer's authorization server to require pushed authorization requests and to
advertise `require_pushed_authorization_requests` as `true`, which here means
setting `OPTION_REQUIRE_PUSHED_AUTHORIZATION_REQUESTS` — off by default. See
[Configuration](3-oidc-configuration.md#pushed-authorization-requests-par-and-request-objects).

A second setting off by default decides whether credentials expire at all. The
profile's requirement here is on *checking* `validFrom` and `validUntil`, which
is a verifier's action and so outside this module's role, but it also recommends
that issuers set an expiration wherever they can — and
`OPTION_VCI_CREDENTIAL_TTLS` names no credential configuration until one is
added, so by default nothing issued carries an expiry. Each format states the
window in the vocabulary of its own data model: `vc+sd-jwt` uses `validFrom` and
`validUntil`, `jwt_vc_json` declares the VCDM 1.1 context and so uses
`issuanceDate` and `expirationDate`, and `dc+sd-jwt` uses the JWT `nbf`; all
three carry `exp` once a lifetime is set. A `jwt_vc_json` or `dc+sd-jwt`
credential will therefore never carry `validUntil`, which is its data model
rather than a gap — but one issued from a configuration with no lifetime carries
no expiry at all, in any of the three. See [Credential
expiry](3-oidc-configuration.md#credential-expiry), which also covers why a
credential that never expires holds its Status List open for good.

A third setting decides whether credentials name a federation at all. The
profile's Trust Establishment section — optional in v5 — profiles OpenID
Federation for credentials in its Appendix B (the *OpenID Federation Digital
Credentials Profile*, "OpenID Fed DCP") and has an Issuer say in each credential
which Entity Configuration a verifier resolves its Trust Chain from: an SD-JWT
VC (`dc+sd-jwt`) carries the issuer URL in a `fed` claim, and a W3C VCDM
credential (`jwt_vc_json`, `vc+sd-jwt`) carries a `termsOfUse` entry of type
`OpenIDFederation` whose `policyId` is that URL. It is the issuer URL under
every issuer identity mode, which is the point of the claim: a verifier holding
a `did:jwk` in `iss` has nothing to fetch an Entity Configuration from. Both are
emitted only while `OPTION_FEDERATION_ENABLED` is on, because that switch is
also what decides whether an Entity Configuration is published at that URL —
with it off, a credential names no federation rather than one that answers 403.

The Entity Configuration a verifier then fetches is profiled by the same
appendix. Beside the `federation_entity` and `openid_provider` metadata it
already carried, it publishes two more entity types. Under
`openid_credential_issuer`, whenever credential issuance is enabled, the
OpenID4VCI issuer metadata — the same document as
`.well-known/openid-credential-issuer`, built once and published twice, because
a wallet which finds it in the Entity Configuration is told to use that copy and
ignore the well-known one; the `credential_issuer` value in it is the Entity
Identifier, as the appendix requires, and both are the issuer URL. Under
`vc_issuer`, a `jwks` holding the keys credentials are signed with. Those are
verification keys, so they follow the credentials rather than the switch: they
are published for as long as the VCI key pairs stay configured, whether or not
issuance is still enabled — which is what the [installation
guide](2-oidc-installation.md) asks of a deployment that turns it off — and
they hold every configured pair and not only the one signing now, so that a
credential signed under a pair since rotated out stays verifiable. A verifier
that has resolved the Trust Chain checks the credential's `kid` header against
that set, and what that header carries depends on the issuer identity mode the
credential was issued under — a `did:jwk` or `did:web` URL under those modes,
the bare key id under `https`. So each key appears under every name a
credential may carry for it: the name of the mode in use, the bare id and the
`did:jwk` URL always, and the `did:web` URL for as long as a `did:web` is
configured, which is also how long its DID document stays published. A
deployment that changes mode therefore keeps its earlier credentials matching.
These keys are distinct from the Entity Configuration's own top-level `jwks`,
which holds the federation keys that sign the statement itself.

Most of the profile's requirements are worded as *"MUST support"* — capabilities
an implementation has to have, rather than a list of things it may not otherwise
do, which is the same reading applied to the `iss` claim above. So the question
worth asking of a deployment is not whether some setting disqualifies it, but
whether a given credential comes out carrying the properties a DIIP verifier
expects. Several independently configured things decide that, and the binding
policy is only one of them:

- the **issuer identity mode** — under `https` a credential names its issuer by
  a URL rather than by a DID;
- the **credential format** — the profile's are the SD-JWT ones, so
  `jwt_vc_json` is not among them;
- the **algorithm of the active signing key** — the profile names ES256, and
  this module permits RSA and the larger EC curves too;
- and the **binding policy** — `DiipProofBound` is what *guarantees* the
  `cnf.kid` names a `did:jwk` or `did:web` verification method, because it
  refuses everything else. `ProofBound` produces the same binding when a wallet
  happens to send such a proof, but it will bind to an inline key or a `did:key`
  holder just as readily, and `Proofless` does not bind at all.

A credential carries the profile's properties where all four line up for it —
the format and the binding policy from its own credential configuration, the
issuer identity and the signing key from the deployment. Only the first three
are settled by configuration alone: under `ProofBound` the binding a credential
ends up with is whichever one the wallet's proof asked for, which is the reason
`DiipProofBound` exists.

## Conformance testing

On every build, CI runs the following OpenID Foundation certification test
plans against the module (using the OpenID conformance suite). See
[OpenID Conformance](5-oidc-conformance.md) for how to run them yourself:

- OpenID Connect Core: Basic OP (`oidcc-basic-certification-test-plan`)
- OpenID Connect Core: Implicit OP (`oidcc-implicit-certification-test-plan`)
- OpenID Connect Core: Form Post Basic OP
  (`oidcc-formpost-basic-certification-test-plan`)
- OpenID Connect Core: Form Post Implicit OP
  (`oidcc-formpost-implicit-certification-test-plan`)
- OpenID Connect RP-Initiated Logout
  (`oidcc-rp-initiated-logout-certification-test-plan`)
- OpenID Connect Back-Channel Logout
  (`oidcc-backchannel-rp-initiated-logout-certification-test-plan`)
- OpenID Connect Core: Dynamic OP
  (`oidcc-dynamic-certification-test-plan`) — exercises Dynamic Client
  Registration. A few tests in this plan cover OP behaviours that are not DCR and
  are not (yet) supported; they are tracked as expected failures. See
  [OpenID Conformance](5-oidc-conformance.md) for details.

Some specifications are not covered by these OpenID Connect certification
profiles. In particular, PAR (RFC 9126) and the `request` / `request_uri`
handling are validated separately: their MUST-level requirements are tracked
and mapped to unit tests in `conformance-tests/rfc9126-par-compliance.md`.

## Version compatibility

Minor versions listed show which SimpleSAMLphp versions were used during
module development. SimpleSAMLphp follows semantic versioning for its
API since v2.0. PHP version requirements may differ.

From v7 the SimpleSAMLphp version is a Composer requirement rather than only a
tested combination: `simplesamlphp/simplesamlphp:^2.5.3.1` is declared in
`composer.json`, so installing into an older host fails at `composer require`
instead of at runtime.

| OIDC module | Tested SimpleSAMLphp |  PHP   |
|:------------|:---------------------|:------:|
| v7\*        | v2.5.3.1             | \>=8.3 |
| v6.4.\*     | v2.5.\*              | \>=8.3 |
| v6.3.\*     | v2.3.\*, v2.4.\*     | \>=8.2 |
| v5.\*       | v2.1.\*              | \>=8.1 |
| v4.\*       | v2.0.\*              | \>=8.0 |
| v3.\*       | v2.0.\*              | \>=7.4 |
| v2.\*       | v1.19.\*             | \>=7.4 |

Upgrading? See the [upgrade guide](6-oidc-upgrade.md).

## Documentation

- Getting started: [Installation](2-oidc-installation.md)
- Configure and operate: [Configuration](3-oidc-configuration.md)
- Manage clients and UI: see [Configuration](3-oidc-configuration.md#relying-party-rp-administration)
- Endpoints and discovery: see
  [Configuration](3-oidc-configuration.md#endpoint-locations-and-well-known-urls)
- Running with containers: [Using Docker](4-oidc-docker.md)
- Conformance tests: [OpenID Conformance](5-oidc-conformance.md)
- Dynamic Client Registration metadata support:
  [DCR client metadata](9-oidc-dcr-client-metadata.md)
- Upgrading between versions: [Upgrade guide](6-oidc-upgrade.md)
- Common questions: [FAQ](7-oidc-faq.md)
- API documentation: [API](8-api.md)
