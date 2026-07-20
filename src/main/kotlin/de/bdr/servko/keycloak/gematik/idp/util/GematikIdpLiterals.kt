/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.util

class GematikIdpLiterals {
    companion object {
        const val START_AUTH_PATH = "startAuth"
        const val AUTH_REQUEST_PATH = "authRequest"
        const val RESULT_PATH = "result"
        const val TIMEOUT_PATH = "timeout"
        const val PREFLIGHT = "preflight"
        const val LOGIN_START_TIME_NOTE = "loginStartTime"
        const val AUTHENTICATION_STATUS = "status"
        const val AUTHENTICATOR_NEXT_STEP = "nextStep"
        const val AUTHENTICATOR_VERSION = "authenticatorVersion"
        const val AUTHENTICATOR_VERSION_PARAM = "authenticator_version"

        const val CHALLENGE_PATH_PARAM = "challenge_path"
        const val CALLBACK = "callback"
        const val CARD_TYPE = "cardType"

        const val TOKEN_KEY = "token_key"
        const val KEY_VERIFIER = "key_verifier"

        const val CODE_VERIFIER = "CODE_VERIFIER"
        const val GEMATIK_IDP_STEP = "GEMATIK_IDP_STEP"
        const val HBA_DATA = "HBA_DATA"
        const val SMCB_DATA = "SMCB_DATA"

        const val ERROR = "error"
        const val ERROR_DETAILS = "error_details"
        const val ERROR_URI = "error_uri"

        const val CONSENT_DECLINED_ERROR = "access_denied"
        const val CONSENT_DECLINED_ERROR_DETAIL = "User declined consent"

        const val AUTHENTICATOR_PORT = "authenticatorPort"
        const val SERVER_PORT_PARAMETER = "server_port"
        // Handshake identifier used by the new‑version authenticator flow.
        const val HANDSHAKE_ID = "handshake_id"
    }
}
