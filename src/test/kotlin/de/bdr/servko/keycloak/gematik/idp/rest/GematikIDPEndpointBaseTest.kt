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

import com.fasterxml.jackson.databind.ObjectMapper
import de.bdr.servko.keycloak.gematik.idp.TestUtils
import de.bdr.servko.keycloak.gematik.idp.exception.SessionNotFoundException
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPState
import de.bdr.servko.keycloak.gematik.idp.service.GematikIDPService
import de.bdr.servko.keycloak.gematik.idp.token.TestTokenUtil
import de.bdr.servko.keycloak.gematik.idp.util.RestClient
import org.assertj.core.api.Assertions
import org.keycloak.OAuth2Constants
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.models.*
import org.keycloak.protocol.oidc.utils.PkceUtils
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.sessions.AuthenticationSessionProvider
import org.keycloak.sessions.RootAuthenticationSessionModel
import org.mockito.ArgumentMatchers
import org.mockito.kotlin.*
import java.net.URI
import javax.ws.rs.core.Response
import javax.ws.rs.core.UriBuilder

abstract class GematikIDPEndpointBaseTest {
    companion object {
        const val REALM_NAME = "test-realm"
        const val IDP_ALIAS = "gematik-idp"
        const val ROOT_SESSION_ID = "rootSessionId"
        const val TAB_ID = "tabId"
        const val CLIENT_ID = "gematik_client"
        const val GEMATIK_CLIENT_ID = "AuthenticatorDevLocalHttps"
        const val CODE = "dg99COL1CfysxnBuUTxz4gjfNdtD6OoCca5sdKwdUSY="
    }

    val state: String = GematikIDPState(ROOT_SESSION_ID, CLIENT_ID, TAB_ID).encode()

    val hbaKeyVerifier: String = PkceUtils.generateCodeVerifier()
    val hbaTokenMock = TestUtils.getJsonHbaToken()
    val smcbKeyVerifier: String = PkceUtils.generateCodeVerifier()
    val smcbTokenMock = TestUtils.getJsonSmcbToken()
    val jwksMock = TestTokenUtil.jwksMock()
    val encJwkMock = TestTokenUtil.encJwkMock()

    val clientMock = mock<ClientModel> {
        on { isEnabled } doReturn true
        on { clientId } doReturn CLIENT_ID
    }

    val realmMock = mock<RealmModel> {
        on { name } doReturn REALM_NAME
        on { getClientByClientId(CLIENT_ID) } doReturn clientMock
    }

    val callbackMock = mock<IdentityProvider.AuthenticationCallback>()

    val authSessionMock = mock<AuthenticationSessionModel> {
        on { realm } doReturn realmMock
        on { client } doReturn clientMock
    }

    val service = mock<GematikIDPService> {
        on { resolveAuthSessionFromEncodedState(any(), any()) } doReturn authSessionMock
    }

    val sessionMock = mock<KeycloakSession> {
        val keycloakUriInfo = mock<KeycloakUriInfo> {
            on { baseUriBuilder } doAnswer { UriBuilder.fromUri("http://localhost:8080") }
        }
        val keycloakContext = mock<KeycloakContext> {
            on { uri } doAnswer { keycloakUriInfo }
            on { realm } doAnswer { realmMock }
        }
        on { context } doReturn keycloakContext
    }

    val rest = mock<RestClient> {
    }

    val authenticationSession = mock<AuthenticationSessionProvider> {
    }

    val rootAuthenticationSession = mock<RootAuthenticationSessionModel> {
    }

    val config: GematikIDPConfig = GematikIDPConfig().apply {
        alias = IDP_ALIAS
        clientId = GEMATIK_CLIENT_ID
        defaultScope = "openid"
        setOpenidConfigUrl("http://localhost:8000/")
        updateOpenidConfig(TestUtils.discoveryDocument)
        setAuthenticatorUrl("http://localhost:8000/")
        setAuthenticatorAuthorizationUrl(TestUtils.discoveryDocument.authorizationEndpoint)
        setTimeoutMs("20000")
        setIdpTimeoutMs("10000")
        setIdpUserAgent("Servko/1.0.0 Servko/Client")
        setMultipleIdentityMode(true)
        setNewAuthenticationFlow(true)
    }

    fun mockDoPostToGetHbaToken() {
        whenever(
            rest.doPost(
                eq(config.tokenUrl),
                ArgumentMatchers.anyMap(),
                eq(config.getIdpTimeoutMs()),
                eq(config.getIdpUserAgent())
            )
        ).thenReturn(ObjectMapper().readTree(hbaTokenMock))
    }

    fun mockDoPostToGetSmcbToken() {
        whenever(
            rest.doPost(
                eq(config.tokenUrl),
                ArgumentMatchers.anyMap(),
                eq(config.getIdpTimeoutMs()),
                eq(config.getIdpUserAgent())
            )
        ).thenReturn(ObjectMapper().readTree(smcbTokenMock))
    }

    fun mockDoGetJwk() {
        whenever(rest.doGet(TestUtils.discoveryDocument.pukEncUri, config.getIdpUserAgent())).thenReturn(encJwkMock)
        whenever(rest.doGet(TestUtils.discoveryDocument.jwksUri, config.getIdpUserAgent())).thenReturn(jwksMock)
    }

    fun testResolveAuthSessionFailure(test: () -> Response) {
        val message = "client not found or disabled"
        whenever(service.resolveAuthSessionFromEncodedState(realmMock, state))
            .thenThrow(SessionNotFoundException(message))
        whenever(callbackMock.error(ArgumentMatchers.anyString())).thenReturn(
            Response.status(Response.Status.INTERNAL_SERVER_ERROR).build()
        )

        Assertions.assertThat(test().statusInfo).isEqualTo(Response.Status.INTERNAL_SERVER_ERROR)

        val errorCaptor = argumentCaptor<String>()
        verify(callbackMock).error(errorCaptor.capture())
        Assertions.assertThat(errorCaptor.firstValue)
            .isEqualTo("Failed to resolve auth session: client not found or disabled")
    }

    fun assertNextStepUrl(statusUrl: URI) {
        Assertions.assertThat(statusUrl)
            .hasHost("localhost")
            .hasPort(8080)
            .hasPath("/realms/test-realm/broker/gematik-idp/endpoint/nextStep")

        val statusUriParams = statusUrl.query.split("&").associate { queryParam ->
            queryParam.split("=").let {
                it[0] to it[1]
            }
        }

        Assertions.assertThat(statusUriParams[OAuth2Constants.STATE]).isEqualTo(state)
    }
}
