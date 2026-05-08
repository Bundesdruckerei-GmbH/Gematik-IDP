# Release Notes

## Release 3.13.0

* Update Keycloak to 26.5.6
* Copyright header update
* LICENSE.md update
* Removal of X-XXS-Protection from GematikIDP-ref-idp.json
* Test update
* Dependency updates

## Release 3.12.0

* Added validation for ID-Token signer certificate against gematik TSL certificate chain
  * Caching mechanism ensures moderate processing load
  * Configurable via admin UI toggle (disabled by default)
* Removed legacy authentication flow
  * Default authentication flow changed from `LEGACY` to `MULTI`
  * Added validation for authentication flow selection on configuration
* Fixed PostgreSQL image version to 16 in `docker-compose.yml`
* Update Keycloak to 26.5.3
  * Migrated to `UserAuthenticationIdentityProvider` API
  * User attribute mapper now uses `USER_PROFILE_ATTRIBUTE_LIST_TYPE`
* Update Kotlin to 2.3.0
* Update gematik IDP reference server to 30.0.3
* Dependency updates

## Release 3.11.0

* Update Keycloak to 26.4.5
    * removed GematikIDP#updateEmail overwrite, as it is handled by Keycloak,
      see [Keycloak Issue-42281](https://github.com/keycloak/keycloak/issues/42281)
* Improved pom.xml dependency management
* Update Kotlin to 2.2.21
* Dependency updates

## Release 3.10.0

* Update Keycloak to 26.3.3
    * Addressed an issue which causes the user email to be overwritten when sync mode is FORCE,
      see [Keycloak Issue-42281](https://github.com/keycloak/keycloak/issues/42281)
* Improved gematik root certificate handling
    * Print missing issuer certificate while building certificate chain
    * Added `gematik-root-certificates/download-certificates.sh` to download and verify gematik root certificates
* Update Kotlin to 2.2.20
* Dependency updates

## Release 3.9.0

* Update Keycloak to 26.3.2
* Resolved [Issue#18 - Validierung des Discovery Dokumentes](https://github.com/Bundesdruckerei-GmbH/Gematik-IDP/issues/18)
    * see Readme chapter _TSL certificate validation_ for more information
* Dependency Updates

## Release 3.8.0

* Added **optional “Authenticator Auto-Launch”** setting  
  *When enabled the confirmation modal is bypassed; when disabled the modal remains for backward compatibility.*
* Update Keycloak to 26.2.5
* Update Kotlin to 2.2.0
* Dependency updates
* Deprecated: The legacy Gematik authentication flow is no longer used and will be removed in a future release.

## Release 3.7.0

* Update Keycloak to 26.2.4
* Dependency updates

## Release 3.6.0

* Update Keycloak to 26.0.7

## Release 3.5.0

* Update Keycloak to 26.0.6
* Dependency updates

## Release 3.4.0

* Dependency updates

## Release 3.3.0

* Dependency updates

## Release 3.2.0

* Update Keycloak to 25.0.6

## Release 3.1.0

* Update Keycloak to 25.0.5

## Release 3.0.0

* Update Keycloak to 25.0.4
* Update Java rom 17 to 21
* Dependency updates

## Release 2.11.0

* Fixed an issue, where a wrongly configured Gematik-IDP url causes an error in Keycloak, which prevented the loading of
  the Gematik-IDP configuration page
* Improved nullability handling of `authenticationSession.getAuthNote(...)` method results
* Add maven profile to exclude theme-resources

## Release 2.10.0

* Update Kotlin to v2.0.0
* Dependency updates

## Release 2.9.0

* Update to Keycloak 24.0.5
* Dependency updates

## Release 2.8.0

* Dependency updates

## Release 2.7.0

* Moved templates and messages into compiled jar
* Added new translation keys

## Release 2.6.0

* Added Attribute Mapper for Gematik-Authenticator HBA & SMCB Consents
* Fixed an issue, where an expired session lead to internal exception in the backend and a stuck login process in the
  frontend
* Update to Keycloak 23

## Release 2.5.0

* Dependency updates

## Release 2.4.0

* Dependency updates

## Release 2.3.0

* Reworked error handling
* Dependency updates

## Release 2.2.0

* Dependency updates

## Release 2.1.0

* Documentation updated
* Fixed an issue, where a timeout of the HBA/SMC-B wasn't correctly handled in the frontend
* Version updates

## Release 2.0.0

* Update to Keycloak 22
* JavaX updated to Jakarta
* Updated to Java 17
* Added preliminary configuration UI for the new admin console
* Removed legacy authentication flow
* Removed authenticator URL setting. ``authenticator://`` is now used as standard
* Removed client assertion signing alg setting in the frontend, since Brainpool is always used for token the validation
* Fixed an issue, where an empty authenticatorAuthorizationUrl lead to a NoSuchElementException while trying to
  authenticate

## Release 1.7.1

* Deleted unused classes
* Dependency updates

## Release 1.7.0

* Integration of version Gematik Authenticator version 4.6.0
* Finalization of the new single HBA and SMC-B authentication flows
* Finalization of the new multi authentication flows

## Release 1.6.0

* Dependency updates

## Release 1.5.0

* Introduced new single HBA and SMC-B authentication flows
* Added new HBA and SMC-B identity providers to the sample realm
* Status endpoint renamed (from `authenticationStatus` to `status`)
* Next-Step endpoint renamed (from `authenticatorNextStep` to `nextStep`)

## Release 1.4.0

* Support for the new multi authentication flow added

## Release 1.3.0

* The Authenticator version is now appended to the MDC and the auth session notes
* Update to Keycloak 21.1.2

## Release 1.2.0

* The parent session id is now included in the encoded state

## Release 1.1.0

* Added support for Keycloak 20
* Added support for the new direct flow of the Gematik-Authenticator
* Added a new modal so users have to acknowledge the call to the Gematik-Authenticator. This was necessary to mitigate
  issues with blocked consecutive calls to external protocol handlers.
