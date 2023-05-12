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

import de.bdr.servko.keycloak.gematik.idp.GematikIDPService
import de.bdr.servko.keycloak.gematik.idp.TestUtils
import org.jose4j.jwt.JwtClaims
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator
import org.keycloak.services.resources.admin.permissions.RealmPermissionEvaluator
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class GematikIDPAdminRestResourceTest {

    private val realmPermissionEvaluator = mock<RealmPermissionEvaluator> {}
    private val realmAuth = mock<AdminPermissionEvaluator> { on { realm() } doReturn realmPermissionEvaluator }

    private val service = mock<GematikIDPService> {}

    private var underTest: GematikIDPAdminRestResource = GematikIDPAdminRestResource(realmAuth, service)

    @Test
    fun openidConfiguration() {
        val jwtClaims = mock<JwtClaims> { on { claimsMap } doReturn emptyMap() }
        val authorizationEndpoint = TestUtils.discoveryDocument.authorizationEndpoint
        val userAgent = "Servko/1.0.0 Servko/Client"

        whenever(service.getOpenIDConfiguration(authorizationEndpoint, userAgent)).thenReturn(jwtClaims)

        val response = underTest.openidConfiguration(authorizationEndpoint, userAgent)

        verify(realmPermissionEvaluator).requireManageIdentityProviders()
        Assertions.assertEquals(200, response.status)
        Assertions.assertTrue((response.entity as Map<*, *>).isEmpty())
    }
}
