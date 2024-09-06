# Release Notes

## Release 3.0.0

* Update Keycloak to 24.0.5
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
