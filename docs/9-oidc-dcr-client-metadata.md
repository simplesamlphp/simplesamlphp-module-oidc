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
| `grant_types` | **Honored** (persist + echo + enforce) | Honored | Default `["authorization_code"]`. Enforced for the code grant; refresh grant exempt (see note). |
| `response_types` | **Honored** (persist + echo + enforce) | Honored | Default `["code"]`. Enforced at the authorization endpoint. |
| `token_endpoint_auth_method` | **Honored** (persist + echo + enforce) | Honored | Default `client_secret_basic` (or `none` for public). Enforced at the token endpoint. |
| `jwks` | Honored | Honored | Stored (column). |
| `jwks_uri` | Honored | Honored | Stored (column); fetched for client auth / request objects. |
| `signed_jwks_uri` | Honored | Honored | Stored (column). |
| `request_uris` | Honored | Honored | Persisted; exact-matched for request_uri by reference; fragment allowed. |
| `post_logout_redirect_uris` | Honored | Honored | |
| `backchannel_logout_uri` | Honored | Honored | |
| `id_token_signed_response_alg` | Honored (rejects unsupported) | Honored | Precedent for "reject unsupported". |
| `application_type` | Validated + echoed | Validated + echoed | `web` / `native`. |
| `contacts` | Validated + echoed | Validated + echoed | |
| `logo_uri` | Validated + echoed | Validated + echoed | Subject to impersonation protection. |
| `policy_uri` | Validated + echoed | Validated + echoed | Subject to impersonation protection. |
| `tos_uri` | Validated + echoed | Validated + echoed | Subject to impersonation protection. |
| `client_uri` | Validated + echoed | Validated + echoed | Excluded from impersonation protection. |
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
| `default_acr_values` | **Honored** (validate + store + echo + enforce) | Honored | Admin-editable. Default applied when acr_values omitted (AcrValuesRule). |
| `initiate_login_uri` | **Validated + echoed** | Validated + echoed | Admin-editable; https URI. Informational. |
| `backchannel_logout_session_required` | Ignored | TBD | |
| `frontchannel_logout_uri` / `..._session_required` | **Reject** if requested | Reject | Front-channel logout not supported. |
| `software_id` / `software_version` | **Validated + echoed** | Validated + echoed | Admin-editable. RFC 7591 informational. |
| `software_statement` | Ignored | TBD | RFC 7591; only if signed-statement trust is implemented. |

## Enforcement policy

Per-client enforcement of `grant_types` / `response_types` /
`token_endpoint_auth_method` is **presence-based**: a field is enforced for a
client only when that client has it explicitly registered. Dynamically registered
clients always do (the OIDC DCR defaults are applied at registration); clients
that do not have it configured are not constrained. This avoids regressing
manually-managed clients while still honoring the registered metadata. All client
metadata is stored in the existing `extra_metadata` JSON column (no DB migration),
and is exposed as editable fields in the admin UI.

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
