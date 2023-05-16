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

import com.fasterxml.jackson.databind.ObjectMapper
import de.bdr.servko.keycloak.gematik.idp.exception.SessionNotFoundException
import de.bdr.servko.keycloak.gematik.idp.extension.BrainpoolCurves
import de.bdr.servko.keycloak.gematik.idp.model.ContextData
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPStatusResponse
import de.bdr.servko.keycloak.gematik.idp.token.TestTokenUtil
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.keycloak.OAuth2Constants
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.common.util.Base64
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.models.*
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.protocol.oidc.utils.PkceUtils
import org.keycloak.sessions.AuthenticationSessionModel
import org.mockito.ArgumentMatchers.anyString
import org.mockito.kotlin.*
import java.net.URI
import javax.ws.rs.core.Response
import javax.ws.rs.core.UriBuilder

internal class GematikIDPEndpointNewAuthFlowTest {

    private val realmName = "test-realm"
    private val idpAlias = "gematik-idp"
    private val clientId = "gematik_client"
    private val hbaKeyVerifier = PkceUtils.generateCodeVerifier()
    private val hbaTokenMock = TestUtils.getJsonHbaToken()
    private val smcbKeyVerifier = PkceUtils.generateCodeVerifier()
    private val smcbTokenMock = TestUtils.getJsonSmcbToken()
    private val jwksMock = TestTokenUtil.jwksMock()
    private val encJwkMock = TestTokenUtil.encJwkMock()

    private val clientMock = mock<ClientModel> {
        on { isEnabled } doReturn true
        on { clientId } doReturn clientId
    }
    private val realmMock = mock<RealmModel> {
        on { name } doReturn realmName
        on { getClientByClientId(clientId) } doReturn clientMock
    }
    private val callbackMock = mock<IdentityProvider.AuthenticationCallback>()
    private val formsMock = mock<LoginFormsProvider> {
        on { setError(anyString(), any()) } doReturn it
        on { setAttribute(anyString(), any()) } doReturn it
        on { createForm(anyString()) } doReturn Response.ok().build()
        on { createErrorPage(any()) } doReturn Response.status(Response.Status.BAD_REQUEST).build()
    }

    private val authSessionMock = mock<AuthenticationSessionModel> {
        on { realm } doReturn realmMock
        on { client } doReturn clientMock
    }

    private val sessionMock = mock<KeycloakSession> {
        val keycloakUriInfo = mock<KeycloakUriInfo> {
            on { baseUriBuilder } doAnswer { UriBuilder.fromUri("http://localhost:8080") }
        }
        val keycloakContext = mock<KeycloakContext> {
            on { uri } doAnswer { keycloakUriInfo }
        }
        on { context } doReturn keycloakContext
    }

    private val gematikClientId = "AuthenticatorDevLocalHttps"
    private val config: GematikIDPConfig = GematikIDPConfig().apply {
        alias = idpAlias
        clientId = gematikClientId
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
    private val idp = GematikIDP(sessionMock, config)

    private var isHba = true

    private val service = mock<GematikIDPService> {
        on { resolveAuthSessionFromEncodedState(any(), any()) }.thenReturn(authSessionMock)
        on { decodeIdentityBrokerState(any()) }.thenCallRealMethod()
        on { getJWKS(any(), any()) }.thenCallRealMethod()
        on { getJWK(any(), any()) }.thenCallRealMethod()
    }

    private val underTest = object : GematikIDPEndpoint(
        realmMock,
        callbackMock,
        sessionMock,
        idp,
        config,
        formsMock,
        service
    ) {
        override fun generateTokenKeyBytes(): ByteArray =
            if (isHba) {
                Base64.decode("dg99COL1CfysxnBuUTxz4gjfNdtD6OoCca5sdKwdUSY=")
            } else {
                Base64.decode("zdztIiMMgVa3jKdvrNG04BtbTZ4TjbbziazVjLLmEbM=")
            }

        override fun skipAllValidators(): Boolean = true
    }

    private val state: String = "$clientId${GematikIDP.STATE_DELIMITER}tabId"
    private val code: String = "dg99COL1CfysxnBuUTxz4gjfNdtD6OoCca5sdKwdUSY="


    @BeforeEach
    fun beforeEach() {
        CryptoIntegration.init(javaClass.classLoader)
        BrainpoolCurves.init()
    }

    @Test
    fun startAuth() {
        // arrange
        val authenticatorUrlCaptor = argumentCaptor<URI>()
        val statusUrlCaptor = argumentCaptor<URI>()

        // act
        assertThat(underTest.startAuth(state).statusInfo).isEqualTo(Response.Status.OK)

        // assert
        verify(formsMock).setAttribute(eq("authenticatorUrl"), authenticatorUrlCaptor.capture())
        val authenticatorUrl = authenticatorUrlCaptor.firstValue
        assertAuthenticatorUrl(authenticatorUrl)

        verify(formsMock).setAttribute(eq("statusUrl"), statusUrlCaptor.capture())
        val statusUrl = statusUrlCaptor.firstValue
        assertStatusUrl(statusUrl)

        verify(formsMock).setAttribute(
            "timeoutUrl",
            URI.create("http://localhost:8080/realms/$realmName/broker/$idpAlias/endpoint/timeout?state=$state")
        )
        verify(formsMock).setAttribute("timeoutMs", 20000)
        verify(formsMock).createForm("gematik-idp.ftl")
    }

    @Test
    fun status_GetStatusHbaRequested() {
        // arrange
        whenever(authSessionMock.getAuthNote("HBA_DATA")).thenReturn(null)
        whenever(authSessionMock.getAuthNote("SMCB_DATA")).thenReturn(null)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPEndpoint.GematikIDPStep.REQUESTED_HBA_DATA.name)

        // act
        val result = underTest.status(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.ACCEPTED)
        assertThat((result.entity as GematikIDPStatusResponse).currentStep)
            .isEqualTo(GematikIDPEndpoint.GematikIDPStep.REQUESTED_HBA_DATA.name)
        assertThat((result.entity as GematikIDPStatusResponse).nextStepUrl).isNull()
    }

    @Test
    fun status_GetStatusSmcbRequested() {
        // arrange
        whenever(authSessionMock.getAuthNote("HBA_DATA")).thenReturn(TestUtils.getJsonHbaToken())
        whenever(authSessionMock.getAuthNote("SMCB_DATA")).thenReturn(null)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPEndpoint.GematikIDPStep.REQUESTED_SMCB_DATA.name)

        // act
        val result = underTest.status(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.ACCEPTED)
        assertThat((result.entity as GematikIDPStatusResponse).currentStep)
            .isEqualTo(GematikIDPEndpoint.GematikIDPStep.REQUESTED_SMCB_DATA.name)
        assertThat((result.entity as GematikIDPStatusResponse).nextStepUrl).isNull()
    }

    @Test
    fun status_GetStatusHbaReceived() {
        // arrange
        whenever(authSessionMock.getAuthNote("HBA_DATA")).thenReturn(TestUtils.getJsonHbaToken())
        whenever(authSessionMock.getAuthNote("SMCB_DATA")).thenReturn(null)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPEndpoint.GematikIDPStep.RECEIVED_HBA_DATA.name)

        // act
        val result = underTest.status(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.OK)
        assertThat((result.entity as GematikIDPStatusResponse).currentStep)
            .isEqualTo(GematikIDPEndpoint.GematikIDPStep.RECEIVED_HBA_DATA.name)
        assertAuthenticatorNextStepUrl((result.entity as GematikIDPStatusResponse).nextStepUrl!!)
    }

    @Test
    fun status_GetStatusSmcbReceived() {
        // arrange
        whenever(authSessionMock.getAuthNote("HBA_DATA")).thenReturn(TestUtils.getJsonHbaToken())
        whenever(authSessionMock.getAuthNote("SMCB_DATA")).thenReturn(TestUtils.getJsonSmcbToken())
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPEndpoint.GematikIDPStep.RECEIVED_SMCB_DATA.name)

        // act
        val result = underTest.status(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.OK)
        assertThat((result.entity as GematikIDPStatusResponse).currentStep)
            .isEqualTo(GematikIDPEndpoint.GematikIDPStep.RECEIVED_SMCB_DATA.name)
        assertAuthenticatorNextStepUrl((result.entity as GematikIDPStatusResponse).nextStepUrl!!)
    }

    @Test
    fun status_GetStatusIdpError() {
        // arrange
        whenever(authSessionMock.getAuthNote("HBA_DATA")).thenReturn(null)
        whenever(authSessionMock.getAuthNote("SMCB_DATA")).thenReturn(null)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPEndpoint.GematikIDPStep.IDP_ERROR.name)

        // act
        val result = underTest.status(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.OK)
        assertThat((result.entity as GematikIDPStatusResponse).currentStep)
            .isEqualTo(GematikIDPEndpoint.GematikIDPStep.IDP_ERROR.name)
        assertAuthenticatorNextStepUrl((result.entity as GematikIDPStatusResponse).nextStepUrl!!)
    }

    @Test
    fun status_InvalidStatusSet_ErrorCallback() {
        // arrange
        whenever(authSessionMock.getAuthNote("HBA_DATA")).thenReturn("")
        whenever(authSessionMock.getAuthNote("SMCB_DATA")).thenReturn("")
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPEndpoint.GematikIDPStep.RECEIVED_SMCB_DATA.name)
        whenever(callbackMock.error(any())).thenReturn(mock())

        // act
        underTest.status(state)

        // assert
        verify(callbackMock).error("Invalid state. Please restart authentication flow.")
    }

    @Test
    fun status_NoAuthSessionFound_ErrorCallback() {
        // arrange
        val message = "AuthenticationSessionModel not found for state $state"
        whenever(service.resolveAuthSessionFromEncodedState(realmMock, state))
            .thenThrow(SessionNotFoundException(message))
        whenever(callbackMock.error(any())).thenReturn(mock())

        // act
        underTest.status(state)

        // assert
        verify(callbackMock).error("Failed to resolve auth session: $message")
    }

    @Test
    fun authenticatorNextStep_ReceivedHbaData() {
        // arrange
        val authenticatorUrlCaptor = argumentCaptor<URI>()
        val statusUrlCaptor = argumentCaptor<URI>()

        whenever(authSessionMock.getAuthNote("CODE_VERIFIER")).thenReturn(hbaKeyVerifier)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPEndpoint.GematikIDPStep.RECEIVED_HBA_DATA.name)
        whenever(callbackMock.authenticated(any())).thenReturn(Response.ok().build())

        // act
        val result = underTest.authenticatorNextStep(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.OK)
        verify(authSessionMock).setAuthNote(
            "GEMATIK_IDP_STEP",
            GematikIDPEndpoint.GematikIDPStep.REQUESTED_SMCB_DATA.name
        )

        verify(formsMock).setAttribute(eq("authenticatorUrl"), authenticatorUrlCaptor.capture())
        val authenticatorUrl = authenticatorUrlCaptor.firstValue
        assertAuthenticatorUrl(authenticatorUrl, "openid Institutions_ID")

        verify(formsMock).setAttribute(eq("statusUrl"), statusUrlCaptor.capture())
        val statusUrl = statusUrlCaptor.firstValue
        assertStatusUrl(statusUrl)

        verify(formsMock).setAttribute(
            "timeoutUrl",
            URI.create("http://localhost:8080/realms/$realmName/broker/$idpAlias/endpoint/timeout?state=$state")
        )
        verify(formsMock).setAttribute("timeoutMs", 20000)
        verify(formsMock).createForm("gematik-idp.ftl")
    }

    @Test
    fun authenticatorNextStep_ReceivedSmcbData() {
        // arrange
        val error = "invalid_scope"
        val errorDetails = "AUTHCL_0001"
        val errorUri = "https://wiki.gematik.de/pages/viewpage.action?pageId=466488828"

        whenever(authSessionMock.getAuthNote("error")).thenReturn(error)
        whenever(authSessionMock.getAuthNote("error_details")).thenReturn(errorDetails)
        whenever(authSessionMock.getAuthNote("error_uri")).thenReturn(errorUri)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPEndpoint.GematikIDPStep.IDP_ERROR.name)

        // act
        val result = underTest.authenticatorNextStep(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.BAD_REQUEST)

        verify(formsMock).setError(
            eq("authenticator.errorIdp"),
            eq(errorDetails)
        )
    }

    @Test
    fun authenticatorNextStep_IdpError() {
        // arrange
        whenever(authSessionMock.getAuthNote("HBA_DATA")).thenReturn(TestUtils.getHbaData())
        whenever(authSessionMock.getAuthNote("SMCB_DATA")).thenReturn(TestUtils.getSmcbData())
        whenever(authSessionMock.getAuthNote("CODE_VERIFIER")).thenReturn(hbaKeyVerifier)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPEndpoint.GematikIDPStep.RECEIVED_SMCB_DATA.name)
        whenever(callbackMock.authenticated(any())).thenReturn(Response.ok().build())

        // act
        val result = underTest.authenticatorNextStep(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.OK)

        val identityCapture = argumentCaptor<BrokeredIdentityContext>()
        verify(callbackMock).authenticated(identityCapture.capture())
        val identityContext = identityCapture.firstValue

        val hbaTelematikID = "1-HBA-Testkarte-883110000129083"
        assertThat(identityContext.id).startsWith(hbaTelematikID)
        assertThat(identityContext.username).isEqualTo(hbaTelematikID)
        assertThat(identityContext.modelUsername).isEqualTo(hbaTelematikID)

        val contextData = identityContext.contextData
        assertThat(contextData).hasSize(9)
        assertThat(contextData[ContextData.CONTEXT_HBA_TELEMATIK_ID.name]).isEqualTo(hbaTelematikID)
        assertThat(contextData[ContextData.CONTEXT_HBA_PROFESSION_OID.name]).isEqualTo("1.2.276.0.76.4.30")
        assertThat(contextData[ContextData.CONTEXT_HBA_GIVEN_NAME.name]).isEqualTo("Roland")
        assertThat(contextData[ContextData.CONTEXT_HBA_FAMILY_NAME.name]).isEqualTo("MaiÞer")
        assertThat(contextData[ContextData.CONTEXT_SMCB_TELEMATIK_ID.name]).isEqualTo("5-SMC-B-Testkarte-883110000129071")
        assertThat(contextData[ContextData.CONTEXT_SMCB_PROFESSION_OID.name]).isEqualTo("1.2.276.0.76.4.53")
        assertThat(contextData[ContextData.CONTEXT_SMCB_ORGANIZATION_NAME.name]).isEqualTo("Universitätsklinik MitteTEST-ONLY")
        assertThat(contextData[ContextData.CONTEXT_SMCB_GIVEN_NAME.name]).isEqualTo("UNKNOWN")
        assertThat(contextData[ContextData.CONTEXT_SMCB_FAMILY_NAME.name]).isEqualTo("UNKNOWN")
    }

    @Test
    fun authenticatorNextStep_NoAuthSessionFound_ErrorCallback() {
        // arrange
        val message = "AuthenticationSessionModel not found for state $state"
        whenever(service.resolveAuthSessionFromEncodedState(realmMock, state))
            .thenThrow(SessionNotFoundException(message))
        whenever(callbackMock.error(any())).thenReturn(mock())

        // act
        underTest.authenticatorNextStep(state)

        // assert
        verify(callbackMock).error("Failed to resolve auth session: $message")
    }

    @Test
    fun result_WithError() {
        // arrange
        val error = "invalid_request"
        val errorDetails = "client_id ist ungültig"
        val errorUri = "https://wiki.gematik.de/x/-A3OGw"

        // act
        val result = underTest.result(code, state, error, errorDetails, errorUri)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.NO_CONTENT)
        verify(authSessionMock).setAuthNote("error", error)
        verify(authSessionMock).setAuthNote("error_details", errorDetails)
        verify(authSessionMock).setAuthNote("error_uri", errorUri)
        verify(authSessionMock).setAuthNote("GEMATIK_IDP_STEP", GematikIDPEndpoint.GematikIDPStep.IDP_ERROR.name)
    }

    @Test
    fun result_SuccessHba() {
        // arrange
        isHba = true
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPEndpoint.GematikIDPStep.REQUESTED_HBA_DATA.name)
        whenever(authSessionMock.getAuthNote("CODE_VERIFIER")).thenReturn(hbaKeyVerifier)
        whenever(service.doGet(TestUtils.discoveryDocument.pukEncUri, config.getIdpUserAgent())).thenReturn(encJwkMock)
        whenever(service.doGet(TestUtils.discoveryDocument.jwksUri, config.getIdpUserAgent())).thenReturn(jwksMock)
        whenever(service.fetchToken(
            eq(config.tokenUrl),
            eq(config.clientId),
            eq("http://localhost:8080/realms/test-realm/broker/gematik-idp/endpoint/result"),
            any(),
            any(),
            eq(config.getIdpTimeoutMs()),
            eq(config.getIdpUserAgent())
        )).thenReturn(ObjectMapper().readTree(hbaTokenMock))

        // act
        val result = underTest.result(code, state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.OK)
        verify(authSessionMock).setAuthNote("GEMATIK_IDP_STEP", GematikIDPEndpoint.GematikIDPStep.RECEIVED_HBA_DATA.name)
        verify(authSessionMock).setAuthNote(eq("HBA_DATA"), any())
    }

    @Test
    fun result_SuccessSmcb() {
        // arrange
        isHba = false
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPEndpoint.GematikIDPStep.REQUESTED_SMCB_DATA.name)
        whenever(authSessionMock.getAuthNote("CODE_VERIFIER")).thenReturn(smcbKeyVerifier)
        whenever(service.doGet(TestUtils.discoveryDocument.pukEncUri, config.getIdpUserAgent())).thenReturn(encJwkMock)
        whenever(service.doGet(TestUtils.discoveryDocument.jwksUri, config.getIdpUserAgent())).thenReturn(jwksMock)
        whenever(service.fetchToken(
            eq(config.tokenUrl),
            eq(config.clientId),
            eq("http://localhost:8080/realms/test-realm/broker/gematik-idp/endpoint/result"),
            any(),
            any(),
            eq(config.getIdpTimeoutMs()),
            eq(config.getIdpUserAgent())
        )).thenReturn(ObjectMapper().readTree(smcbTokenMock))

        // act
        val result = underTest.result(code, state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.OK)
        verify(authSessionMock).setAuthNote("GEMATIK_IDP_STEP", GematikIDPEndpoint.GematikIDPStep.RECEIVED_SMCB_DATA.name)
        verify(authSessionMock).setAuthNote(eq("SMCB_DATA"), any())
    }

    @Test
    fun result_NoAuthSessionFound_ErrorCallback() {
        // arrange
        val message = "AuthenticationSessionModel not found for state $state"
        whenever(service.resolveAuthSessionFromEncodedState(realmMock, state))
            .thenThrow(SessionNotFoundException(message))
        whenever(callbackMock.error(any())).thenReturn(mock())

        // act
        underTest.result(code, state)

        // assert
        verify(callbackMock).error("Failed to resolve auth session: $message")
    }

    private fun assertAuthenticatorUrl(authenticatorUrl: URI, scope: String = "openid Person_ID") {
        assertThat(authenticatorUrl)
            .hasHost("localhost")
            .hasPort(8000)
            .hasPath("/")
        assertThat(authenticatorUrl.toString()).contains("callback=direct")
        val queryParams = authenticatorUrl.query.split("=", "&", limit = 2)
        assertThat(queryParams).hasSize(2)
        assertThat(queryParams[0]).isEqualTo("challenge_path")
        val challengeUri = URI.create(queryParams[1].replace(" ", "%20"))
        assertThat(challengeUri)
            .hasHost("host.docker.internal")
            .hasPort(8081)
            .hasPath("/sign_response")
        val challengeQueryParams = challengeUri.query.split("&").associate { queryParam ->
            queryParam.split("=").let {
                it[0] to it[1]
            }
        }

        assertThat(challengeQueryParams[OAuth2Constants.CLIENT_ID]).isEqualTo(gematikClientId)
        assertThat(challengeQueryParams[OAuth2Constants.RESPONSE_TYPE]).isEqualTo(OAuth2Constants.CODE)
        assertThat(challengeQueryParams[OAuth2Constants.REDIRECT_URI]).isEqualTo("http://localhost:8080/realms/$realmName/broker/$idpAlias/endpoint/result")
        assertThat(challengeQueryParams[OAuth2Constants.STATE]).isEqualTo(state)
        assertThat(challengeQueryParams[OAuth2Constants.SCOPE]).isEqualTo(scope)
        assertThat(challengeQueryParams[OAuth2Constants.CODE_CHALLENGE]).isNotBlank
        assertThat(challengeQueryParams[OAuth2Constants.CODE_CHALLENGE_METHOD]).isEqualTo(OAuth2Constants.PKCE_METHOD_S256)
        assertThat(challengeQueryParams[OIDCLoginProtocol.NONCE_PARAM]).isNotBlank
    }

    private fun assertStatusUrl(statusUrl: URI) {
        assertThat(statusUrl)
            .hasHost("localhost")
            .hasPort(8080)
            .hasPath("/realms/test-realm/broker/gematik-idp/endpoint/authenticationStatus")

        val statusUriParams = statusUrl.query.split("&").associate { queryParam ->
            queryParam.split("=").let {
                it[0] to it[1]
            }
        }

        assertThat(statusUriParams[OAuth2Constants.STATE]).isEqualTo(state)
    }

    private fun assertAuthenticatorNextStepUrl(statusUrl: URI) {
        assertThat(statusUrl)
            .hasHost("localhost")
            .hasPort(8080)
            .hasPath("/realms/test-realm/broker/gematik-idp/endpoint/authenticatorNextStep")

        val statusUriParams = statusUrl.query.split("&").associate { queryParam ->
            queryParam.split("=").let {
                it[0] to it[1]
            }
        }

        assertThat(statusUriParams[OAuth2Constants.STATE]).isEqualTo(state)
    }
}
