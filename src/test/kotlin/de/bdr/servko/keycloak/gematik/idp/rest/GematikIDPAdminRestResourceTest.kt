/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.TestUtils
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpOpenIDConfigurationService
import org.jose4j.jwt.JwtClaims
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator
import org.keycloak.services.resources.admin.fgap.RealmPermissionEvaluator
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class GematikIDPAdminRestResourceTest {

    private val realmPermissionEvaluator = mock<RealmPermissionEvaluator> {}
    private val realmAuth = mock<AdminPermissionEvaluator> { on { realm() } doReturn realmPermissionEvaluator }

    private val service = mock<GematikIdpOpenIDConfigurationService> {}

    private var underTest: GematikIDPAdminRestResource = GematikIDPAdminRestResource(realmAuth, service)

    @Test
    fun openidConfiguration() {
        val jwtClaims = mock<JwtClaims> { on { claimsMap } doReturn emptyMap() }
        val authorizationEndpoint = TestUtils.discoveryDocument.authorizationEndpoint
        val userAgent = "Servko/1.0.0 Servko/Client"

        whenever(service.getOpenIDConfiguration(authorizationEndpoint, userAgent, false)).thenReturn(jwtClaims)

        val response = underTest.openidConfiguration(authorizationEndpoint, userAgent, false)

        verify(realmPermissionEvaluator).requireManageIdentityProviders()
        Assertions.assertEquals(200, response.status)
        Assertions.assertTrue((response.entity as Map<*, *>).isEmpty())
    }
}
