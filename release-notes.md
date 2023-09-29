# Release Notes

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
* Added a new modal so users have to acknowledge the call to the Gematik-Authenticator. This was necessary to mitigate issues with blocked consecutive calls to external protocol handlers.
