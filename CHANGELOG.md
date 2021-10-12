# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [2.0.0-rc.1] - 2021-10-08
### Added
- Implicit flow support
- Back-channel logout
- RP initiated logout
- Support for 'sid' claim in ID and logout token
- Support for claim types
- Allow users with specific entitlements to add clients
- Support for ACR
- Support for requesting individual claims
- Support for allowed CORS origins for public clients
- Support for 'at_hash' claim in ID token
- Support for 'max_age' parameter
- List of supported grant types in OP configuration document
- List of supported auth methods for token endpoint in OP configuration document
- Support for 'prompt' parameter, for example using 'prompt=login' to require authentication
even if user has active SSO session
- Works with SSP new UI templating enabled
- Pagination for client list
- Support for basic authentication processing filters, for example for f-ticks logging, attribute
manipulation or similar, definable in oidc_config.php
- Support for 'nonce' claim in ID token
- Config options to add prefix to private scope claims and to enable multi-valued claims
### Changed
- Basic flow is now conformant
- Admin client configuration path has moved
- 'token_endpoint' renamed form '.../access_token.php' to '.../token.php' 
- Requires php > 7.4
- Auth. source is now optional when defining clients. If auth. source is not set for particular 
client, a default one from the configuration will be used during authn.
### Fixed
- When authorization code is reused corresponding tokens are now immediately revoked
- Returning or displaying proper error messages is now more in line to specification
- Expired access tokens are now only deleted if corresponding refresh tokens are also expired
- JWT header parameter 'kid' is now generated dynamically based on public certificate fingerprint

## [1.0.0-rc.2] - 2020-05-17
### Added
- Second release candidate
- Updated league/oauth2-server to version 8.1
### Changed
- Removed pkce config option
- New field _is_confidential_ in client (disabled for previous clients)
- Update database schema

## [1.0.0-rc.1] - 2018-11-13
### Added
- First release candidate
### Changed
- BC: Config file (`module_oidc.php`) has changed. Predefined scopes must be removed: openid, profile, mail, address, phone.


## [1.0.0-alpha.1] - 2018-04-11
### Added
- First pre-release
