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
 *
 */

package de.bdr.servko.keycloak.gematik.idp

import de.bdr.servko.keycloak.gematik.idp.extension.BrainpoolCurves
import de.bdr.servko.keycloak.gematik.idp.model.GematikDiscoveryDocument
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import org.keycloak.broker.provider.AbstractIdentityProviderFactory
import org.keycloak.models.IdentityProviderModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ServerInfoAwareProviderFactory
import java.time.Clock
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.annotation.Generated

class GematikIDPFactory : AbstractIdentityProviderFactory<GematikIDP>(), ServerInfoAwareProviderFactory {
    companion object {
        const val PROVIDER_ID = "gematik-idp"
    }

    private val discoveryDocumentCache = ConcurrentHashMap<String, GematikDiscoveryDocument>()
    override fun getId(): String = PROVIDER_ID
    override fun getName(): String = "Gematik IDP"

    override fun postInit(factory: KeycloakSessionFactory?) {
        BrainpoolCurves.init()
    }

    @Generated
    override fun create(session: KeycloakSession, model: IdentityProviderModel): GematikIDP =
        createAndUpdateConfig(session, GematikIDPConfig(model))

    fun createAndUpdateConfig(
        session: KeycloakSession,
        config: GematikIDPConfig,
        clock: Clock = Clock.systemUTC(),
        serviceFactory: (KeycloakSession) -> GematikIDPService = { GematikIDPService(it) }
    ): GematikIDP {
        val openidConfiguration = discoveryDocumentCache.compute(config.getOpenidConfigUrl()) { url, document ->
            if (document == null || document.expiration < clock.millis()) {
                GematikDiscoveryDocument(serviceFactory(session).getOpenIDConfiguration(url, config.getIdpUserAgent()))
            } else {
                document
            }
        }
        config.updateOpenidConfig(openidConfiguration!!)
        return GematikIDP(session, config)
    }

    override fun createConfig(): IdentityProviderModel = GematikIDPConfig()
    override fun getOperationalInfo(): Map<String, String> =
        javaClass
            .getResourceAsStream("/META-INF/maven/de.bdr.servko/gematik-idp/pom.properties")
            ?.let {
                val prop = Properties()
                try {
                    prop.load(it)
                } catch (e: Exception) {
                    //ignore
                }
                mapOf("Version" to prop.getProperty("version", "unknown"))
            } ?: mapOf("Version" to "unknown")

}
