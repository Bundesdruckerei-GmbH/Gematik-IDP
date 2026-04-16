/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.model

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.models.IdentityProviderModel
import org.keycloak.models.RealmModel
import de.bdr.servko.keycloak.gematik.idp.exception.InvalidAuthenticationFlowException


class GematikIDPConfig(model: IdentityProviderModel? = null) : OIDCIdentityProviderConfig(model) {

    companion object {
        const val AUTHENTICATOR_AUTHORIZATION_URL = "authenticatorAuthorizationUrl"
        const val OPENID_CONFIG_URL = "openidConfigUrl"
        const val VALIDATE_TOKEN_SIGNER_CERTIFICATE = "validateTokenSignerCertificate"
        const val VALIDATE_OPENID_CONFIG_SIGNING_CERTIFICATE = "validateOpenIDConfigSigningCertificate"
        const val TIMEOUT_MS = "timeoutMs"
        const val IDP_TIMEOUT_MS = "idpTimeoutMs"
        const val IDP_USER_AGENT = "idpUserAgent"
        const val MULTIPLE_IDENTITY_MODE = "multipleIdentityMode"
        const val AUTHENTICATION_FLOW = "authenticationFlow"
        const val AUTHENTICATOR_AUTO_LAUNCH = "authenticatorAutoLaunch"
    }

    fun setAuthenticatorAuthorizationUrl(url: String) = config.put(AUTHENTICATOR_AUTHORIZATION_URL, url)
    fun getAuthenticatorAuthorizationUrl(): String =
        config[AUTHENTICATOR_AUTHORIZATION_URL]?.takeIf { it.isNotBlank() } ?: authorizationUrl

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
    fun getTimeoutMs() = config[TIMEOUT_MS]?.toIntOrNull() ?: 20000

    fun setIdpTimeoutMs(ms: String) = config.put(IDP_TIMEOUT_MS, ms)
    fun getIdpTimeoutMs() = config[IDP_TIMEOUT_MS]?.toIntOrNull() ?: 10000

    fun setIdpUserAgent(userAgent: String) = config.put(IDP_USER_AGENT, userAgent)
    fun getIdpUserAgent(): String = config.getValue(IDP_USER_AGENT)

    fun setMultipleIdentityMode(multipleIdentityMode: Boolean) =
        config.put(MULTIPLE_IDENTITY_MODE, multipleIdentityMode.toString())
    fun getMultipleIdentityMode() = config[MULTIPLE_IDENTITY_MODE]?.toBoolean() == true

    fun setAuthenticatorAutoLaunch(authenticatorAutoLaunch: Boolean) =
        config.put(AUTHENTICATOR_AUTO_LAUNCH, authenticatorAutoLaunch.toString())

    fun getAuthenticatorAutoLaunch() = config[AUTHENTICATOR_AUTO_LAUNCH]?.toBoolean() == true

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
        if (AuthenticationFlowType.entries.none { it.name == config[AUTHENTICATION_FLOW] }) {
            throw InvalidAuthenticationFlowException("Authentication flow '${config[AUTHENTICATION_FLOW]}' is not valid")
        }
        super.validate(realm)
    }
}
