/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.tsl.TslCertificateVerifierProvider
import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.services.resources.admin.AdminEventBuilder
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock

class GematikIDPAdminRestResourceFactoryTest {
    private val keycloakSession = mock<KeycloakSession> {
        val keycloakContext = mock<KeycloakContext> {
            on { realm } doReturn mock()
        }
        on { context } doReturn keycloakContext
        on { getProvider(TslCertificateVerifierProvider::class.java) } doReturn mock<TslCertificateVerifierProvider>()
    }
    private val realmAuth = mock<AdminPermissionEvaluator> {}
    private val adminEvent = mock<AdminEventBuilder> {}
    private val realm = mock<RealmModel> {}

    private var underTest: GematikIDPAdminRestResourceFactory = GematikIDPAdminRestResourceFactory()

    @Test
    fun getIdTest() {
        val factoryId: String = underTest.getId()
        assertThat(factoryId).isEqualTo("adm-gematik-idp")
    }

    @Test
    fun getOperationalInfo() {
        assertThat(underTest.operationalInfo)
            .contains(Assertions.entry("Version", "unknown"))
    }

    @Test
    fun getResource() {
        val resource = underTest.getResource(keycloakSession, realm, realmAuth, adminEvent)
        assertThat(resource).isInstanceOf(GematikIDPAdminRestResource::class.java)
    }
}
