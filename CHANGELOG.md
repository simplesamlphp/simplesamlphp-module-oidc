# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [2.0.0-rc.1] - 2021-10-08
### Added
- Implicit flow support
- Backchannel logout
- RP initiated logout
- Add support for claim types
- Allow users with specific entitlements to add clients
- Support for ACR
- Support for requesting individual claims
- Works with SSP new UI templating enabled
### Changed
- Basic flow is now conformant
- Admin client configuration path has moved
- Requires php > 7.4

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
