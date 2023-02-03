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

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.keycloak.broker.provider.AuthenticationRequest
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.broker.provider.util.IdentityBrokerState
import org.keycloak.events.EventBuilder
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakUriInfo
import org.keycloak.models.RealmModel
import org.keycloak.sessions.AuthenticationSessionModel
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.net.URI
import java.util.*
import javax.ws.rs.core.Response
import javax.ws.rs.core.UriBuilder

internal class GematikIDPTest {
    private val realmName = "test-realm"
    private val idpAlias = "gematik-idp"
    private val config: GematikIDPConfig = GematikIDPConfig().apply {
        alias = idpAlias
    }
    private val realm = mock<RealmModel> {
        on { name } doReturn realmName
    }
    private val authSession = mock<AuthenticationSessionModel> {
        on { realm } doReturn realm
    }
    private val request = mock<AuthenticationRequest> {
        on { authenticationSession } doReturn authSession
    }
    private val keycloakUriInfo = mock<KeycloakUriInfo> {
        on { baseUriBuilder } doReturn UriBuilder.fromUri("http://localhost:8080")
    }
    private val keycloakContext = mock<KeycloakContext> {
        on { uri } doReturn keycloakUriInfo
    }
    private val session = mock<KeycloakSession> {
        on { context } doReturn keycloakContext
    }

    private val objectUnderTest: GematikIDP = GematikIDP(session, config)

    @Test
    fun performLogin() {
        val performLogin = objectUnderTest.performLogin(request)
        assertThat(performLogin.status).isEqualTo(Response.Status.SEE_OTHER.statusCode)
        assertThat(performLogin.location).isEqualTo(URI.create("http://localhost:8080/realms/$realmName/broker/$idpAlias/endpoint/startAuth"))
    }

    @Test
    fun performLogin_withState() {
        val clientId = "gematik_client"
        val tabId = "tab123"
        whenever(request.state).thenReturn(
            IdentityBrokerState.decoded(
                UUID.randomUUID().toString(), clientId, tabId
            )
        )

        val performLogin = objectUnderTest.performLogin(request)
        assertThat(performLogin.status).isEqualTo(Response.Status.SEE_OTHER.statusCode)
        assertThat(performLogin.location).isEqualTo(URI.create("http://localhost:8080/realms/$realmName/broker/$idpAlias/endpoint/startAuth?state=$clientId${GematikIDP.STATE_DELIMITER}$tabId"))
    }

    @Test
    fun callback() {
        val formsProvider = mock<LoginFormsProvider>()
        whenever(session.getProvider(LoginFormsProvider::class.java)).thenReturn(formsProvider)
        val authenticationCallback = mock<IdentityProvider.AuthenticationCallback>()
        val eventBuilder = mock<EventBuilder>()

        assertThat(objectUnderTest.callback(realm, authenticationCallback, eventBuilder))
            .isInstanceOf(GematikIDPEndpoint::class.java)
    }
}
