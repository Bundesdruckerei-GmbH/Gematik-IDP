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

import de.bdr.servko.keycloak.gematik.idp.GematikIDP
import de.bdr.servko.keycloak.gematik.idp.extension.BrainpoolCurves
import de.bdr.servko.keycloak.gematik.idp.model.ContextData
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPStep
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpCertificateService
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.keycloak.OAuth2Constants
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.common.util.Base64
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.forms.login.freemarker.model.ClientBean
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.mockito.ArgumentMatchers.anyString
import org.mockito.kotlin.*
import java.net.URI
import javax.ws.rs.core.Response

internal class GematikIDPLegacyResourceTest: GematikIDPEndpointBaseTest() {
    private val formsMock = mock<LoginFormsProvider> {
        on { setAttribute(anyString(), any()) } doReturn it
        on { createForm(anyString()) } doReturn Response.ok().build()
    }

    val idp = GematikIDP(sessionMock, config)

    var isHba = true

    private val restService = object : GematikIdpCertificateService(realmMock, sessionMock, config, rest) {
        override fun generateTokenKeyBytes(): ByteArray =
            if (isHba) {
                Base64.decode("dg99COL1CfysxnBuUTxz4gjfNdtD6OoCca5sdKwdUSY=")
            } else {
                Base64.decode("zdztIiMMgVa3jKdvrNG04BtbTZ4TjbbziazVjLLmEbM=")
            }

        override fun skipAllValidators(): Boolean = true
    }

    private val objectUnderTest = GematikIDPLegacyResource(
        realmMock,
        callbackMock,
        sessionMock,
        idp,
        config,
        service,
        formsMock,
        restService
    )

    @BeforeEach
    fun beforeEach() {
        CryptoIntegration.init(javaClass.classLoader)
        BrainpoolCurves.init()
        config.setNewAuthenticationFlow(false)
    }

    @Test
    fun `timeout - returns correct form response`() {
        objectUnderTest.timeout(state)

        val capture = argumentCaptor<ClientBean>()
        verify(formsMock).setAttribute(eq("client"), capture.capture())
        val clientBean = capture.firstValue
        assertThat(clientBean.clientId).isEqualTo(CLIENT_ID)

        verify(formsMock).createForm("gematik-idp-timeout.ftl")
    }

    @Test
    fun `timeout - resolveAuthSession fails`() {
        testResolveAuthSessionFailure {
            objectUnderTest.timeout(state)
        }
    }

    @Test
    fun `startAuth - returns correct form response`() {
        assertThat(objectUnderTest.startAuth(state).statusInfo).isEqualTo(Response.Status.OK)

        val authenticatorUrlCaptor = argumentCaptor<URI>()

        verify(formsMock).setAttribute(eq("authenticatorUrl"), authenticatorUrlCaptor.capture())
        val authenticatorUrl = authenticatorUrlCaptor.firstValue
        assertAuthenticatorUrl(authenticatorUrl)

        verify(formsMock).setAttribute(
            "timeoutUrl",
            URI.create("http://localhost:8080/realms/$REALM_NAME/broker/$IDP_ALIAS/endpoint/timeout?state=$state")
        )
        verify(formsMock, never()).setAttribute(
            eq("statusUrl"),
            any()
        )
        verify(formsMock).setAttribute("timeoutMs", 20000)
        verify(formsMock).createForm("gematik-idp.ftl")
    }

    @Test
    fun `startAuth resolveAuthSession fails`() {
        testResolveAuthSessionFailure {
            objectUnderTest.startAuth(state)
        }
    }

    @Test
    fun resultPost() {
        assertThat(objectUnderTest.resultPost().statusInfo).isEqualTo(Response.Status.FOUND)
    }

    @Test
    fun `result - end to end test of login process`() {
        mockDoGetJwk()

        whenever(authSessionMock.getAuthNote(GematikIdpLiterals.CODE_VERIFIER)).thenReturn(hbaKeyVerifier)
        whenever(authSessionMock.getAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP))
            .thenReturn(GematikIDPStep.REQUESTED_HBA_DATA.name)

        mockDoPostToGetHbaToken()

        val hbaResult = objectUnderTest.result("", state)
        assertThat(hbaResult.statusInfo).isEqualTo(Response.Status.OK)

        val hbaCapture = argumentCaptor<String>()
        verify(authSessionMock).setAuthNote(eq(GematikIdpLiterals.HBA_DATA), hbaCapture.capture())
        verify(authSessionMock).setAuthNote(
            GematikIdpLiterals.GEMATIK_IDP_STEP,
            GematikIDPStep.RECEIVED_HBA_DATA.name
        )
        verify(authSessionMock).setAuthNote(
            GematikIdpLiterals.GEMATIK_IDP_STEP,
            GematikIDPStep.REQUESTED_SMCB_DATA.name
        )

        isHba = false

        mockDoPostToGetSmcbToken()

        whenever(authSessionMock.getAuthNote(GematikIdpLiterals.CODE_VERIFIER)).thenReturn(smcbKeyVerifier)
        whenever(authSessionMock.getAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP))
            .thenReturn(GematikIDPStep.REQUESTED_SMCB_DATA.name)
        whenever(authSessionMock.getAuthNote(GematikIdpLiterals.HBA_DATA)).thenReturn(hbaCapture.firstValue)
        whenever(callbackMock.authenticated(any())).thenReturn(Response.ok().build())

        val smcbResult = objectUnderTest.result("", state)
        assertThat(smcbResult.statusInfo).isEqualTo(Response.Status.OK)

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
        assertThat(contextData[ContextData.CONTEXT_SMCB_TELEMATIK_ID.name])
            .isEqualTo("5-SMC-B-Testkarte-883110000129071")
        assertThat(contextData[ContextData.CONTEXT_SMCB_PROFESSION_OID.name]).isEqualTo("1.2.276.0.76.4.53")
        assertThat(contextData[ContextData.CONTEXT_SMCB_ORGANIZATION_NAME.name])
            .isEqualTo("Universitätsklinik MitteTEST-ONLY")
        assertThat(contextData[ContextData.CONTEXT_SMCB_GIVEN_NAME.name]).isEqualTo("UNKNOWN")
        assertThat(contextData[ContextData.CONTEXT_SMCB_FAMILY_NAME.name]).isEqualTo("UNKNOWN")
    }

    @Test
    fun `result - HBA data doesn't get written into SMC-B fields on second try`() {
        mockDoGetJwk()
        mockDoPostToGetHbaToken()

        whenever(authSessionMock.getAuthNote(GematikIdpLiterals.CODE_VERIFIER)).thenReturn(hbaKeyVerifier)
        whenever(authSessionMock.getAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP))
            .thenReturn(GematikIDPStep.REQUESTED_HBA_DATA.name)

        val hbaResult = objectUnderTest.result("", state)
        assertThat(hbaResult.statusInfo).isEqualTo(Response.Status.OK)

        val hbaCapture = argumentCaptor<String>()
        verify(authSessionMock).setAuthNote(eq(GematikIdpLiterals.HBA_DATA), hbaCapture.capture())
        verify(authSessionMock).setAuthNote(
            GematikIdpLiterals.GEMATIK_IDP_STEP,
            GematikIDPStep.RECEIVED_HBA_DATA.name
        )

        isHba = true

        whenever(authSessionMock.getAuthNote(GematikIdpLiterals.CODE_VERIFIER)).thenReturn(smcbKeyVerifier)
        whenever(authSessionMock.getAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP))
            .thenReturn(GematikIDPStep.RECEIVED_HBA_DATA.name)
        whenever(authSessionMock.getAuthNote(GematikIdpLiterals.HBA_DATA)).thenReturn(hbaCapture.firstValue)
        whenever(callbackMock.authenticated(any())).thenReturn(Response.ok().build())

        val smcbResult = objectUnderTest.result("", state)
        assertThat(smcbResult.statusInfo).isEqualTo(Response.Status.OK)

        verify(callbackMock, never()).authenticated(any())
    }

    @Test
    fun `result resolveAuthSession fails`() {
        testResolveAuthSessionFailure {
            objectUnderTest.result("", state)
        }
    }

    @Test
    fun `result receive error`() {
        val error = "invalid_scope"
        val errorDetails = "AUTHCL_0001"
        val errorUri = "https://wiki.gematik.de/pages/viewpage.action?pageId=466488828"

        whenever(formsMock.setError(anyString(), any())).thenReturn(formsMock)
        whenever(formsMock.createErrorPage(Response.Status.BAD_REQUEST))
            .thenReturn(Response.status(Response.Status.BAD_REQUEST).build())

        val result = objectUnderTest.result(
            null,
            null,
            null,
            error,
            errorDetails,
            errorUri
        )

        assertThat(result.statusInfo).isEqualTo(Response.Status.BAD_REQUEST)

        val errorCaptor = argumentCaptor<String>()
        val errorParamCaptor = argumentCaptor<String>()
        verify(formsMock).setError(errorCaptor.capture(), errorParamCaptor.capture())
        assertThat(errorCaptor.firstValue).isEqualTo("authenticator.errorIdp")
        assertThat(errorParamCaptor.firstValue).isEqualTo(errorDetails)
    }

    private fun assertAuthenticatorUrl(authenticatorUrl: URI, scope: String = "openid Person_ID") {
        assertThat(authenticatorUrl)
            .hasHost("localhost")
            .hasPort(8000)
            .hasPath("/")
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

        assertThat(challengeQueryParams[OAuth2Constants.CLIENT_ID]).isEqualTo(GEMATIK_CLIENT_ID)
        assertThat(challengeQueryParams[OAuth2Constants.RESPONSE_TYPE]).isEqualTo(OAuth2Constants.CODE)
        assertThat(challengeQueryParams[OAuth2Constants.REDIRECT_URI]).isEqualTo(
            "http://localhost:8080/realms/$REALM_NAME/broker/$IDP_ALIAS/endpoint/result"
        )
        assertThat(challengeQueryParams[OAuth2Constants.STATE]).isEqualTo(state)
        assertThat(challengeQueryParams[OAuth2Constants.SCOPE]).isEqualTo(scope)
        assertThat(challengeQueryParams[OAuth2Constants.CODE_CHALLENGE]).isNotBlank
        assertThat(challengeQueryParams[OAuth2Constants.CODE_CHALLENGE_METHOD]).isEqualTo(OAuth2Constants.PKCE_METHOD_S256)
        assertThat(challengeQueryParams[OIDCLoginProtocol.NONCE_PARAM]).isNotBlank
    }
}
