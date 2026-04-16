/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.model

enum class AuthenticatorErrorTypes(var error: String) {
    LOGIN_TIMEOUT("loginTimeout"),
    NON_FINAL_STEP("authenticator.nonFinalStep"),
    INCOMPLETE_IDP_DATA("authenticator.incompleteIdpData"),
    UNSUPPORTED_CARD_TYPE("authenticator.unsupportedCardType"),
    UNSUPPORTED_AUTHENTICATOR_VERSION("authenticator.unsupportedAuthenticatorVersion"),
    CONSENT_DECLINED("authenticator.consentDeclined"),
    ERROR_IDP("authenticator.errorIdp");

    companion object {
        fun valueOf(type: String?): AuthenticatorErrorTypes {
            return when(type) {
                LOGIN_TIMEOUT.error -> LOGIN_TIMEOUT
                NON_FINAL_STEP.error -> NON_FINAL_STEP
                INCOMPLETE_IDP_DATA.error -> INCOMPLETE_IDP_DATA
                UNSUPPORTED_AUTHENTICATOR_VERSION.error -> UNSUPPORTED_AUTHENTICATOR_VERSION
                UNSUPPORTED_CARD_TYPE.error -> UNSUPPORTED_CARD_TYPE
                CONSENT_DECLINED.error -> CONSENT_DECLINED
                else -> ERROR_IDP
            }
        }
    }
}
