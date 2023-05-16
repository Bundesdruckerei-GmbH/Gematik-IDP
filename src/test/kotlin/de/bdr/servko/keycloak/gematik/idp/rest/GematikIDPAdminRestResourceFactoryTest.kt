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
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.services.resources.admin.AdminEventBuilder
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock

class GematikIDPAdminRestResourceFactoryTest {
    private val keycloakSession = mock<KeycloakSession> {
        val keycloakContext = mock<KeycloakContext> { on { realm }.doReturn(mock {}) }
        on { context }.thenReturn(keycloakContext)
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
