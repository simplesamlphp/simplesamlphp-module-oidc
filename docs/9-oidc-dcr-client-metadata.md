# OIDC Module - Dynamic Client Registration metadata support

This matrix tracks how the module handles each client metadata field defined by
[OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
(Section 2) and [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) (OAuth 2.0
Dynamic Client Registration), when received at the Dynamic Client Registration
(DCR) endpoint.

The intent is that this table is the source of truth for the per-field policy.
Each field falls into one of these behaviors:

- **Honored** — validated (where applicable), persisted, used to drive OP
  behavior, and returned in the registration/read response.
- **Validated + echoed** — validated and stored/returned, but informational only
  (no behavioral enforcement on the OP).
- **Inferred only** — read to derive something else, then discarded (not stored,
  not returned, not enforced).
- **Rejected** — if the client requests it and the OP cannot honor it, the
  registration is rejected with `invalid_client_metadata` (rather than silently
  ignoring it and behaving differently than the client asked).
- **Ignored** — accepted but dropped; not returned (the omission signals to the
  client that it was not registered).

Per RFC 7591 §3.2.1 the registration response returns the metadata the OP
actually registered (including OP-applied defaults), so the response is the
contract for what was honored.

## Matrix

| Field | Current behavior | Proposed behavior | Notes |
|---|---|---|---|
| `redirect_uris` | Honored | Honored | Required; scheme required, fragment rejected. |
| `client_name` | Honored | Honored | Defaults to client_id. |
| `scope` | Honored | Honored | DCR default = `OPTION_DCR_DEFAULT_SCOPES`. |
| `grant_types` | **Honored** (persist + echo + enforce) | Honored | DCR default `["authorization_code"]` stored at registration. Enforced for the code grant (presence + non-empty); refresh grant exempt (see note). |
| `response_types` | **Honored** (persist + echo + enforce) | Honored | DCR default `["code"]` stored at registration. Enforced at the authorization endpoint (presence + non-empty). |
| `token_endpoint_auth_method` | **Honored** (persist + echo + enforce) | Honored | DCR default `client_secret_basic` (or `none` for public) stored at registration. Enforced at the token endpoint (presence). Also the primary signal for the client type (see below): `none` ⇒ public, any real method ⇒ confidential. |
| `jwks` | Honored | Honored | Stored (column). |
| `jwks_uri` | Honored | Honored | Stored (column); fetched for client auth / request objects. |
| `signed_jwks_uri` | Honored | Honored | Stored (column). |
| `request_uris` | Honored | Honored | Persisted; exact-matched for request_uri by reference; fragment allowed. |
| `post_logout_redirect_uris` | Honored | Honored | |
| `backchannel_logout_uri` | Honored | Honored | |
| `id_token_signed_response_alg` | Honored (rejects unsupported) | Honored | Precedent for "reject unsupported". |
| `application_type` | Validated + echoed | Validated + echoed | Admin-editable. `web` / `native`. |
| `contacts` | Validated + echoed | Validated + echoed | Admin-editable. |
| `logo_uri` | Validated + echoed | Validated + echoed | Admin-editable. Subject to impersonation protection (DCR path). |
| `policy_uri` | Validated + echoed | Validated + echoed | Admin-editable. Subject to impersonation protection (DCR path). |
| `tos_uri` | Validated + echoed | Validated + echoed | Admin-editable. Subject to impersonation protection (DCR path). |
| `client_uri` | Validated + echoed | Validated + echoed | Admin-editable. Excluded from impersonation protection. |
| `client_registration_types` | Honored (federation) | Honored | OpenID Federation. |
| `subject_type` | **Reject** if not `public` | Reject if not `public` | Only `public` is supported (no pairwise). |
| `sector_identifier_uri` | **Reject** if requested | Reject | Pairwise/sector grouping not supported. |
| `userinfo_signed_response_alg` | **Reject** if requested | Reject | Signed UserInfo not supported (conformance `userinfo-rs256`). |
| `userinfo_encrypted_response_alg` / `..._enc` | **Reject** if requested | Reject | Response encryption not supported. |
| `id_token_encrypted_response_alg` / `..._enc` | **Reject** if requested | Reject | Response encryption not supported. |
| `request_object_signing_alg` | Ignored | TBD | Decide once request object policy is finalized. |
| `request_object_encryption_alg` / `..._enc` | **Reject** if requested | Reject | Request object encryption not supported. |
| `token_endpoint_auth_signing_alg` | Ignored | TBD | Relevant to `private_key_jwt` / `client_secret_jwt`. |
| `default_max_age` | **Honored** (validate + store + echo + enforce) | Honored | Admin-editable. Default applied when max_age omitted (MaxAgeRule). |
| `require_auth_time` | **Honored** (validate + store + echo + enforce) | Honored | Admin-editable. Forces auth_time into the ID Token (MaxAgeRule -> AuthCodeGrant). |
| `default_acr_values` | **Honored** (validate + store + echo + enforce) | Honored | Constrained to `acr_values_supported`: DCR rejects unsupported values; the admin field is a multi-select of the supported ACRs. Default applied when acr_values omitted (AcrValuesRule). |
| `initiate_login_uri` | **Validated + echoed** | Validated + echoed | Admin-editable; https URI. Informational. |
| `backchannel_logout_session_required` | Ignored | TBD | |
| `frontchannel_logout_uri` / `..._session_required` | **Reject** if requested | Reject | Front-channel logout not supported. |
| `software_id` / `software_version` | **Validated + echoed** | Validated + echoed | Admin-editable. RFC 7591 informational. |
| `software_statement` | Ignored | TBD | RFC 7591; only if signed-statement trust is implemented. |

## `response_type` ↔ `grant_type` correspondence

OpenID Connect Dynamic Client Registration 1.0 requires that the `grant_types`
list include the grant type(s) corresponding to each registered `response_type`
(`code` → `authorization_code`; `id_token` / `id_token token` → `implicit`). The OP
**normalizes** rather than rejects: when a client registers `response_types`, the
required grant types are merged into `grant_types` (and echoed back per RFC 7591
§3.2.1), so a client that legally omits `grant_types` while declaring a non-`code`
response type still gets a consistent, usable registration. The same normalization
runs on save in the admin UI, and the admin form additionally selects the required
grant types live as the response types are chosen (the JavaScript and the server
share one correspondence map, `ResponseTypeGrantTypeCorrespondence`). `refresh_token`
has no response-type correspondence (it is gated by `offline_access`).

## Client type (confidential / public)

The OAuth 2.0 client type (RFC 6749 §2.1) is not a DCR metadata field, but it is a
real, stored client property (`is_confidential`) that the OP and the underlying
OAuth2 library need at runtime (e.g. PKCE requirement for public clients, whether a
client secret is required / echoed). It is kept in lockstep with
`token_endpoint_auth_method`, which is the DCR signal for it: **`none` ⇒ public, any
real authentication method ⇒ confidential** (`application_type: native` is a secondary
hint used only when no auth method is resolved). This is derived at registration and
re-derived on RFC 7592 updates, and the admin form keeps the confidential/public
choice and the auth-method selection consistent (live in the UI and normalized on
save). When no auth method is set (e.g. a federation/manual client), the explicit
`is_confidential` value stands.

## Enforcement policy

Per-client enforcement of `grant_types` / `response_types` /
`token_endpoint_auth_method` is **presence-based**: a field is enforced for a
client only when that client has it explicitly registered. For the array-valued
fields (`grant_types`, `response_types`) a present-but-**empty** list also counts as
"not configured" and is not enforced (it never means "allow nothing"; this matches
the admin form's "if none are selected, the client is not restricted"). Dynamically
registered clients always have these stored (the OIDC DCR defaults are applied at
registration); clients that do not have them configured are not constrained. This
avoids regressing manually-managed and pre-DCR clients while still honoring the
registered metadata. All client metadata is stored in the existing `extra_metadata`
JSON column (no DB migration), and is exposed as editable fields in the admin UI.

### Single source of truth (v7 transition)

The entity getters for these fields (`getGrantTypes()`, `getResponseTypes()`,
`getTokenEndpointAuthMethod()`) return the **raw registered value** — an empty array
/ `null` when the client has nothing registered — rather than synthesizing the OIDC
DCR spec default. This keeps the stored value the single source of truth, so:

- the admin UI shows exactly what is registered (a pre-DCR client shows these fields
  as unset, not as phantom defaults), and saving such a client does not silently
  impose constraints;
- the registration response still echoes the spec defaults, because for dynamic
  registrations those defaults are persisted at registration time (in
  `ClientEntityFactory`), not invented at read time.

A future major version may move the spec defaults into the getters themselves (so an
unset value resolves to the spec default everywhere). v7 deliberately does not, to
give deployments a transition window in which to set explicit values on clients that
predate these properties.

## Implementation order

1. **`grant_types`, `response_types`, `token_endpoint_auth_method`** — promoted
   from "inferred only" to persisted + echoed + enforced (presence-based), and
   exposed as editable fields in the admin UI (multi-selects for grant/response
   types, a select for the auth method), stored in `extra_metadata`. **Done**
   (conformance plan stays green).
2. **Reject** the unsupported security-relevant fields (signed/encrypted
   UserInfo, response/request-object encryption, `subject_type` non-`public`,
   `sector_identifier_uri`, front-channel logout) instead of silently ignoring.
   **Done** — rejected in `ClientMetadataValidator` with `invalid_client_metadata`
   (conformance `oidcc-userinfo-rs256` now fails at the registration step, recorded
   accordingly in `dynamic-warnings.json`; the plan stays green).
3. **Validate + store (+ enforce/echo)** the remaining benign behavioral fields
   (`default_max_age`, `require_auth_time`, `default_acr_values`,
   `initiate_login_uri`, `software_*`). **Done** — all validated, persisted, echoed
   and admin-editable; the three behavioral defaults are enforced presence-based in
   the authorization flow (`MaxAgeRule` for default_max_age + require_auth_time,
   `AcrValuesRule` for default_acr_values). `software_statement` remains out of scope
   (would require signed-statement trust). Conformance plan stays green.

## Note: `grant_types` vs `offline_access` / refresh tokens

Strict `grant_types` enforcement interacts subtly with refresh tokens. A client
may register `grant_types: ["authorization_code"]` (no `refresh_token`), be
granted `offline_access`, receive a refresh token, and then use the
`refresh_token` grant. The OpenID conformance `oidcc-refresh-token` test does
exactly this. Strictly requiring `refresh_token` in `grant_types` before allowing
the refresh grant would therefore break that flow. The chosen policy must account
for this (e.g. treat a client granted `offline_access` as implicitly permitted to
use the `refresh_token` grant, or add `refresh_token` to the registered
`grant_types` when `offline_access` is in scope).
