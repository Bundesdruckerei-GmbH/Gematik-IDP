/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.model

import de.bdr.servko.keycloak.gematik.idp.exception.InvalidAuthenticationFlowException
import de.bdr.servko.keycloak.gematik.idp.exception.InvalidAuthenticatorPortRangeException
import de.bdr.servko.keycloak.gematik.idp.exception.InvalidAuthenticatorVersionException
import de.bdr.servko.keycloak.gematik.idp.util.DEFAULT_AUTHENTICATOR_HTTP_SERVER_TIMEOUT_MS_VALUE
import de.bdr.servko.keycloak.gematik.idp.util.DEFAULT_AUTHENTICATOR_TIMEOUT_MS_VALUE
import de.bdr.servko.keycloak.gematik.idp.util.DEFAULT_IDP_TIMEOUT_MS_VALUE
import de.bdr.servko.keycloak.gematik.idp.util.DEFAULT_LOGIN_TIMEOUT_MS_VALUE
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.models.IdentityProviderModel
import org.keycloak.models.RealmModel


class GematikIDPConfig(model: IdentityProviderModel? = null) : OIDCIdentityProviderConfig(model) {

    companion object {
        const val AUTHENTICATOR_AUTHORIZATION_URL = "authenticatorAuthorizationUrl"
        const val AUTHENTICATOR_VERSION = "authenticatorVersion"
        const val OPENID_CONFIG_URL = "openidConfigUrl"
        const val VALIDATE_TOKEN_SIGNER_CERTIFICATE = "validateTokenSignerCertificate"
        const val VALIDATE_OPENID_CONFIG_SIGNING_CERTIFICATE = "validateOpenIDConfigSigningCertificate"
        const val TIMEOUT_MS = "timeoutMs"
        const val AUTHENTICATOR_HTTP_SERVER_TIMEOUT_MS = "authenticatorHttpServerTimeoutMs"
        const val LOGIN_TIMEOUT_MS = "loginTimeoutMs"
        const val IDP_TIMEOUT_MS = "idpTimeoutMs"
        const val IDP_USER_AGENT = "idpUserAgent"
        const val MULTIPLE_IDENTITY_MODE = "multipleIdentityMode"
        const val AUTHENTICATION_FLOW = "authenticationFlow"
        const val AUTHENTICATOR_AUTO_LAUNCH = "authenticatorAutoLaunch"
        val MINIMUM_AUTHENTICATOR_VERSION = AuthenticatorVersion(4, 6, 0)
        const val AUTHENTICATOR_PORT_RANGE_START = "authenticatorPortRangeStart"
        const val AUTHENTICATOR_PORT_RANGE_END = "authenticatorPortRangeEnd"
        const val AUTHENTICATOR_MIN_PORT = 1024
        const val AUTHENTICATOR_MAX_PORT = 65535
    }

    fun setAuthenticatorAuthorizationUrl(url: String) = config.put(AUTHENTICATOR_AUTHORIZATION_URL, url)
    fun getAuthenticatorAuthorizationUrl(): String =
        config[AUTHENTICATOR_AUTHORIZATION_URL]?.takeIf { it.isNotBlank() } ?: authorizationUrl

    fun setAuthenticatorVersion(version: String) = config.put(AUTHENTICATOR_VERSION, version)
    fun getAuthenticatorVersion(): String =
        config[AUTHENTICATOR_VERSION]?.takeIf { it.isNotBlank() } ?: MINIMUM_AUTHENTICATOR_VERSION.toString()

    fun setOpenidConfigUrl(url: String) = config.put(OPENID_CONFIG_URL, url)
    fun getOpenidConfigUrl(): String = config.getValue(OPENID_CONFIG_URL)

    fun setValidateTokenSignerCertificate(enabled: Boolean) =
        config.put(VALIDATE_TOKEN_SIGNER_CERTIFICATE, enabled.toString())

    fun getValidateTokenSignerCertificate() =
        config[VALIDATE_TOKEN_SIGNER_CERTIFICATE]?.toBoolean() ?: false

    fun setValidateOpenIDConfigSigningCertificate(enabled: Boolean) =
        config.put(VALIDATE_OPENID_CONFIG_SIGNING_CERTIFICATE, enabled.toString())

    fun getValidateOpenIDConfigSigningCertificate() =
        config[VALIDATE_OPENID_CONFIG_SIGNING_CERTIFICATE]?.toBoolean() ?: false

    lateinit var openidConfig: GematikDiscoveryDocument
    fun updateOpenidConfig(config: GematikDiscoveryDocument) {
        openidConfig = config
        authorizationUrl = config.authorizationEndpoint
        tokenUrl = config.tokenEndpoint
        jwksUrl = config.jwksUri
    }

    fun setTimeoutMs(ms: String) = config.put(TIMEOUT_MS, ms)
    fun getTimeoutMs() = config[TIMEOUT_MS]?.toIntOrNull() ?: DEFAULT_AUTHENTICATOR_TIMEOUT_MS_VALUE

    fun setLoginTimeoutMs(ms: String) = config.put(LOGIN_TIMEOUT_MS, ms)
    fun getLoginTimeoutMs() = config[LOGIN_TIMEOUT_MS]?.toIntOrNull() ?: DEFAULT_LOGIN_TIMEOUT_MS_VALUE

    fun setIdpTimeoutMs(ms: String) = config.put(IDP_TIMEOUT_MS, ms)
    fun getIdpTimeoutMs() = config[IDP_TIMEOUT_MS]?.toIntOrNull() ?: DEFAULT_IDP_TIMEOUT_MS_VALUE

    fun setIdpUserAgent(userAgent: String) = config.put(IDP_USER_AGENT, userAgent)
    fun getIdpUserAgent(): String = config.getValue(IDP_USER_AGENT)

    fun setMultipleIdentityMode(multipleIdentityMode: Boolean) =
        config.put(MULTIPLE_IDENTITY_MODE, multipleIdentityMode.toString())

    fun getMultipleIdentityMode() = config[MULTIPLE_IDENTITY_MODE]?.toBoolean() == true

    fun setAuthenticatorAutoLaunch(authenticatorAutoLaunch: Boolean) =
        config.put(AUTHENTICATOR_AUTO_LAUNCH, authenticatorAutoLaunch.toString())

    fun getAuthenticatorAutoLaunch() = config[AUTHENTICATOR_AUTO_LAUNCH]?.toBoolean() == true

    fun setAuthenticatorPortRangeStart(value: Int) = config.put(AUTHENTICATOR_PORT_RANGE_START, value.toString())
    fun getAuthenticatorPortRangeStart(): Int =
        config[AUTHENTICATOR_PORT_RANGE_START]?.toIntOrNull() ?: AUTHENTICATOR_MIN_PORT

    fun setAuthenticatorPortRangeEnd(value: Int) = config.put(AUTHENTICATOR_PORT_RANGE_END, value.toString())
    fun getAuthenticatorPortRangeEnd(): Int =
        config[AUTHENTICATOR_PORT_RANGE_END]?.toIntOrNull() ?: AUTHENTICATOR_MAX_PORT

    fun setAuthenticatorHttpServerTimeoutMs(ms: String) = config.put(AUTHENTICATOR_HTTP_SERVER_TIMEOUT_MS, ms)
    fun getAuthenticatorHttpServerTimeoutMs() =
        config[AUTHENTICATOR_HTTP_SERVER_TIMEOUT_MS]?.toIntOrNull()
            ?: DEFAULT_AUTHENTICATOR_HTTP_SERVER_TIMEOUT_MS_VALUE

    fun setAuthenticationFlow(authenticationFlow: AuthenticationFlowType) =
        config.put(AUTHENTICATION_FLOW, authenticationFlow.toString())

    fun getAuthenticationFlow(): AuthenticationFlowType {
        return AuthenticationFlowType.entries.find { it.name == config[AUTHENTICATION_FLOW] }
            ?: AuthenticationFlowType.MULTI
    }

    override fun getDefaultScope(): String {
        var defaultScope = super.getDefaultScope() ?: "openid"

        return run {
            if (!defaultScope.contains("openid")) {
                defaultScope += " openid"
            }
            defaultScope
        }
    }

    override fun isCaseSensitiveOriginalUsername(): Boolean {
        return true
    }

    override fun validate(realm: RealmModel?) {
        config[AUTHENTICATION_FLOW]
            ?.takeIf { it.isNotBlank() }
            ?.let { flow ->
                if (AuthenticationFlowType.entries.none { it.name == flow }) {
                    throw InvalidAuthenticationFlowException(flow)
                }
            }
        validateAuthenticatorPortRange(getAuthenticatorPortRangeStart(), getAuthenticatorPortRangeEnd())
        config[AUTHENTICATOR_VERSION]
            ?.takeIf { it.isNotBlank() }
            ?.let { rawVersion ->
                val version = AuthenticatorVersion.from(rawVersion)
                if (version.isNullOrEmpty() || !version.isGreaterThenOrEqual(MINIMUM_AUTHENTICATOR_VERSION)) {
                    throw InvalidAuthenticatorVersionException(rawVersion)
                }
            }
        super.validate(realm)
    }

    /**
     * Validates that the provided start and end ports used for the local HTTP server form a sensible range.
     * Throws [de.bdr.servko.keycloak.gematik.idp.exception.InvalidAuthenticatorPortRangeException] if the range is invalid.
     *
     * This private helper ensures that a configured free‑port range is valid:
     *   1. `start` must be within the globally allowed limits (`MIN_PORT`‑`MAX_PORT`).
     *   2. `end` must also be within those limits.
     *   3. `start` must not be greater than `end` (otherwise the range would be inverted).
     */
    private fun validateAuthenticatorPortRange(start: Int, end: Int) {
        // Validate lower bound for start
        if (start !in AUTHENTICATOR_MIN_PORT..AUTHENTICATOR_MAX_PORT) {
            throw InvalidAuthenticatorPortRangeException(
                "authenticatorPortRangeStart must be between $AUTHENTICATOR_MIN_PORT and $AUTHENTICATOR_MAX_PORT (got $start)"
            )
        }

        // Validate upper bound for end
        if (end !in AUTHENTICATOR_MIN_PORT..AUTHENTICATOR_MAX_PORT) {
            throw InvalidAuthenticatorPortRangeException(
                "authenticatorPortRangeEnd must be between $AUTHENTICATOR_MIN_PORT and $AUTHENTICATOR_MAX_PORT (got $end)"
            )
        }

        // Validate range order
        if (start > end) {
            throw InvalidAuthenticatorPortRangeException(
                "authenticatorPortRangeStart ($start) must be <= authenticatorPortRangeEnd ($end)"
            )
        }
    }
}
