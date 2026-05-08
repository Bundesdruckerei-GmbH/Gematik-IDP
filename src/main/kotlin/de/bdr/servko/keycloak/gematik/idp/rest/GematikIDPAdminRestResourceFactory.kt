/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpOpenIDConfigurationService
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.models.RealmModel
import org.keycloak.provider.ServerInfoAwareProviderFactory
import org.keycloak.services.resources.admin.AdminEventBuilder
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator
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
        adminEvent: AdminEventBuilder,
    ) = GematikIDPAdminRestResource(auth, GematikIdpOpenIDConfigurationService(session))

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
                } catch (_: Exception) {
                    //ignore
                }
                mapOf("Version" to prop.getProperty("version", "unknown"))
            } ?: mapOf("Version" to "unknown")
}
