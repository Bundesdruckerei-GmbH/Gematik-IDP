package de.bdr.servko.keycloak.gematik.idp.util

const val DEFAULT_AUTHENTICATOR_TIMEOUT_MS_VALUE: Int = 20_000 // 20 seconds
const val DEFAULT_IDP_TIMEOUT_MS_VALUE: Int = 10_000 // 10 seconds
const val DEFAULT_AUTHENTICATOR_HTTP_SERVER_TIMEOUT_MS_VALUE: Int = 10_000 // 10 seconds
const val DEFAULT_LOGIN_TIMEOUT_MS_VALUE: Int = 600_000 // 10 minutes
const val AUTHENTICATOR_VERSION_NEW_FLOW: String = "4.17.0"
const val AUTHORIZE_ENDPOINT: String = "/authorize"
const val STATUS_ENDPOINT: String = "/status"
const val LOCALHOST: String = "http://localhost:"
