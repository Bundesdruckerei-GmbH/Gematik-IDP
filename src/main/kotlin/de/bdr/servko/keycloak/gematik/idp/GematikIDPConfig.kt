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

package de.bdr.servko.keycloak.gematik.idp

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.models.IdentityProviderModel

class GematikIDPConfig(model: IdentityProviderModel? = null) : OIDCIdentityProviderConfig(model) {

    fun setAuthenticatorUrl(url: String) = config.put("authenticatorUrl", url)
    fun getAuthenticatorUrl() = config["authenticatorUrl"]!!

    fun setAuthenticatorAuthorizationUrl(url: String) = config.put("authenticatorAuthorizationUrl", url)
    fun getAuthenticatorAuthorizationUrl() = config["authenticatorAuthorizationUrl"]!!

    fun setOpenidConfigUrl(url: String) = config.put("openidConfigUrl", url)
    fun getOpenidConfigUrl() = config["openidConfigUrl"]!!

    lateinit var openidConfig: GematikDiscoveryDocument
    fun updateOpenidConfig(config: GematikDiscoveryDocument) {
        openidConfig = config
        authorizationUrl = config.authorizationEndpoint
        tokenUrl = config.tokenEndpoint
        jwksUrl = config.jwksUri
    }

    fun setTimeoutMs(ms: String) = config.put("timeoutMs", ms)
    fun getTimeoutMs() = config["timeoutMs"]?.toIntOrNull() ?: 20000

    fun setIdpTimeoutMs(ms: String) = config.put("idpTimeoutMs", ms)
    fun getIdpTimeoutMs() = config["idpTimeoutMs"]?.toIntOrNull() ?: 10000

    fun setIdpUserAgent(userAgent: String) = config.put("idpUserAgent", userAgent)
    fun getIdpUserAgent() = config["idpUserAgent"]!!

    override fun getDefaultScope(): String {
        var defaultScope = super.getDefaultScope() ?: "openid"

        return run {
            if (!defaultScope.contains("openid")) {
                defaultScope += " openid"
            }
            defaultScope
        }
    }

}
