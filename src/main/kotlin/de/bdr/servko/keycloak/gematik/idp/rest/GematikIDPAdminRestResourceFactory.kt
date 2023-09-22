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

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpOpenIDConfigurationService
import de.bdr.servko.keycloak.gematik.idp.util.RestClient
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.models.RealmModel
import org.keycloak.provider.ServerInfoAwareProviderFactory
import org.keycloak.services.resources.admin.AdminEventBuilder
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator
import java.util.*

class GematikIDPAdminRestResourceFactory : AdminRealmResourceProvider, AdminRealmResourceProviderFactory,
    ServerInfoAwareProviderFactory {

    // this id is part of the rest-endpoint, e.g. .../admin/realms/<realm>/adm-gematik-idp
    override fun getId(): String = "adm-gematik-idp"

    override fun create(session: KeycloakSession): GematikIDPAdminRestResourceFactory = this

    override fun getResource(
        session: KeycloakSession,
        realm: RealmModel,
        auth: AdminPermissionEvaluator,
        adminEvent: AdminEventBuilder
    ) = GematikIDPAdminRestResource(auth, GematikIdpOpenIDConfigurationService(RestClient(session)))

    override fun init(config: Config.Scope) {
        // do nothing
    }

    override fun postInit(factory: KeycloakSessionFactory) {
        // do nothing
    }

    override fun close() {
        // do nothing
    }

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
