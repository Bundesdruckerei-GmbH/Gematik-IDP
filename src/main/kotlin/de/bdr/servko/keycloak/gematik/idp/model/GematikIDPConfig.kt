/*
 *  Copyright 2023 Bundesdruckerei GmbH and/or its affiliates
 *  and other contributors.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package de.bdr.servko.keycloak.gematik.idp.model

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.models.IdentityProviderModel


class GematikIDPConfig(model: IdentityProviderModel? = null) : OIDCIdentityProviderConfig(model) {

    companion object {
        private const val AUTHENTICATOR_AUTHORIZATION_URL = "authenticatorAuthorizationUrl"
        private const val OPENID_CONFIG_URL = "openidConfigUrl"
        private const val TIMEOUT_MS = "timeoutMs"
        private const val IDP_TIMEOUT_MS = "idpTimeoutMs"
        private const val IDP_USER_AGENT = "idpUserAgent"
        private const val MULTIPLE_IDENTITY_MODE = "multipleIdentityMode"
        private const val AUTHENTICATION_FLOW = "authenticationFlow"
    }

    fun setAuthenticatorAuthorizationUrl(url: String) = config.put(AUTHENTICATOR_AUTHORIZATION_URL, url)
    fun getAuthenticatorAuthorizationUrl(): String =
        config[AUTHENTICATOR_AUTHORIZATION_URL]?.takeIf { it.isNotBlank() } ?: authorizationUrl

    fun setOpenidConfigUrl(url: String) = config.put(OPENID_CONFIG_URL, url)
    fun getOpenidConfigUrl(): String = config.getValue(OPENID_CONFIG_URL)

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

    fun setAuthenticationFlow(authenticationFlow: AuthenticationFlowType) =
        config.put(AUTHENTICATION_FLOW, authenticationFlow.toString())

    fun getAuthenticationFlow(): AuthenticationFlowType {
        return AuthenticationFlowType.entries.find { it.name == config[AUTHENTICATION_FLOW] }
            ?: AuthenticationFlowType.LEGACY
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

}
