package de.bdr.servko.keycloak.gematik.idp

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import de.bdr.servko.keycloak.gematik.idp.extension.BrainpoolCurves
import de.bdr.servko.keycloak.gematik.idp.token.TestTokenUtil
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.keycloak.OAuth2Constants
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.common.util.Base64
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.forms.login.freemarker.model.ClientBean
import org.keycloak.models.*
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.protocol.oidc.utils.PkceUtils
import org.keycloak.services.managers.AuthenticationSessionManager
import org.keycloak.sessions.AuthenticationSessionModel
import org.mockito.ArgumentMatchers.anyString
import org.mockito.kotlin.*
import java.net.URI
import javax.ws.rs.core.Response
import javax.ws.rs.core.UriBuilder

internal class GematikIDPEndpointTest {

    private val realmName = "test-realm"
    private val idpAlias = "gematik-idp"
    private val clientId = "gematik_client"

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
        on { setAttribute(anyString(), any()) } doReturn it
        on { createForm(anyString()) } doReturn Response.ok().build()
    }

    private val authSessionMock = mock<AuthenticationSessionModel> {
        on { realm } doReturn realmMock
        on { client } doReturn clientMock
    }
    private val authSessionManagerMock = mock<AuthenticationSessionManager> {
        on { getCurrentAuthenticationSession(realmMock, clientMock, "tabId") } doReturn authSessionMock
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
        updateOpenidConfig(TestUtils.discoveryDocument)
        setAuthenticatorUrl("http://localhost:8000/")
        setAuthenticatorAuthorizationUrl(TestUtils.discoveryDocument.authorizationEndpoint)
        setTimeoutMs("20000")
        setIdpTimeoutMs("10000")
        setIdpUserAgent("Servko/1.0.0 Servko/Client")
    }
    private val idp = GematikIDP(sessionMock, config)

    private var isHba = true
    private val jwksMock = TestTokenUtil.jwksMock()
    private val encJwkMock = TestTokenUtil.encJwkMock()
    private val hbaKeyVerifier = PkceUtils.generateCodeVerifier()
    private val hbaTokenMock = TestUtils.getJsonHbaToken()
    private val smcbKeyVerifier = PkceUtils.generateCodeVerifier()
    private val smcbTokenMock = TestUtils.getJsonSmcbToken()

    private val service = object : GematikIDPService(sessionMock) {
        override fun doGet(idpUrl: String, userAgent: String): String {
            if (idpUrl == TestUtils.discoveryDocument.pukEncUri) {
                return encJwkMock
            } else if (idpUrl == TestUtils.discoveryDocument.jwksUri) {
                return jwksMock
            }
            return super.doGet(idpUrl, userAgent)
        }

        override fun doPost(idpUrl: String, paramMap: Map<String, String>, timoutMs: Int, userAgent: String): JsonNode {
            return if (isHba) {
                ObjectMapper().readTree(hbaTokenMock)
            } else {
                ObjectMapper().readTree(smcbTokenMock)
            }
        }

        override fun skipAllValidators(): Boolean = true
    }

    private val objectUnderTest = object : GematikIDPEndpoint(
        realmMock,
        callbackMock,
        sessionMock,
        idp,
        config,
        formsMock,
        service,
        authSessionManagerMock
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

    @Test
    fun startAuth() {
        assertThat(objectUnderTest.startAuth(state).statusInfo).isEqualTo(Response.Status.OK)

        val authenticatorUrlCaptor = argumentCaptor<URI>()

        verify(formsMock).setAttribute(eq("authenticatorUrl"), authenticatorUrlCaptor.capture())
        val authenticatorUrl = authenticatorUrlCaptor.firstValue
        assertAuthenticatorUrl(authenticatorUrl)

        verify(formsMock).setAttribute(
            "timeoutUrl",
            URI.create("http://localhost:8080/realms/$realmName/broker/$idpAlias/endpoint/timeout?state=$state")
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
    fun timeout() {
        objectUnderTest.timeout(state)

        val capture = argumentCaptor<ClientBean>()
        verify(formsMock).setAttribute(eq("client"), capture.capture())
        val clientBean = capture.firstValue
        assertThat(clientBean.clientId).isEqualTo(clientId)

        verify(formsMock).createForm("gematik-idp-timeout.ftl")
    }

    @Test
    fun `timeout resolveAuthSession fails`() {
        testResolveAuthSessionFailure {
            objectUnderTest.timeout(state)
        }
    }

    @Test
    fun resultPost() {
        assertThat(objectUnderTest.resultPost().statusInfo).isEqualTo(Response.Status.FOUND)
    }

    @Test
    fun result() {
        CryptoIntegration.init(javaClass.classLoader)
        BrainpoolCurves.init()

        whenever(authSessionMock.getAuthNote(GematikIDPEndpoint.CODE_VERIFIER)).thenReturn(hbaKeyVerifier)
        whenever(authSessionMock.getAuthNote(GematikIDPEndpoint.GEMATIK_IDP_STEP)).thenReturn(GematikIDPEndpoint.GematikIDPStep.STARTING_AUTHENTICATOR.name)

        val hbaResult = objectUnderTest.result("", state)
        assertThat(hbaResult.statusInfo).isEqualTo(Response.Status.FOUND)
        assertAuthenticatorUrl(hbaResult.location, "openid Institutions_ID")

        val hbaCapture = argumentCaptor<String>()
        verify(authSessionMock).setAuthNote(eq(GematikIDPEndpoint.HBA_DATA), hbaCapture.capture())
        verify(authSessionMock).setAuthNote(
            GematikIDPEndpoint.GEMATIK_IDP_STEP,
            GematikIDPEndpoint.GematikIDPStep.RECEIVED_HBA_DATA.name
        )

        isHba = false

        whenever(authSessionMock.getAuthNote(GematikIDPEndpoint.CODE_VERIFIER)).thenReturn(smcbKeyVerifier)
        whenever(authSessionMock.getAuthNote(GematikIDPEndpoint.GEMATIK_IDP_STEP)).thenReturn(GematikIDPEndpoint.GematikIDPStep.RECEIVED_HBA_DATA.name)
        whenever(authSessionMock.getAuthNote(GematikIDPEndpoint.HBA_DATA)).thenReturn(hbaCapture.firstValue)
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
        assertThat(contextData[ContextData.CONTEXT_SMCB_TELEMATIK_ID.name]).isEqualTo("5-SMC-B-Testkarte-883110000129071")
        assertThat(contextData[ContextData.CONTEXT_SMCB_PROFESSION_OID.name]).isEqualTo("1.2.276.0.76.4.53")
        assertThat(contextData[ContextData.CONTEXT_SMCB_ORGANIZATION_NAME.name]).isEqualTo("Universitätsklinik MitteTEST-ONLY")
        assertThat(contextData[ContextData.CONTEXT_SMCB_GIVEN_NAME.name]).isEqualTo("UNKNOWN")
        assertThat(contextData[ContextData.CONTEXT_SMCB_FAMILY_NAME.name]).isEqualTo("UNKNOWN")
    }

    @Test
    fun `result resolveAuthSession fails`() {
        testResolveAuthSessionFailure {
            objectUnderTest.result("", state)
        }
    }

    @Test
    fun `result receive error`() {
        whenever(formsMock.setError(anyString(), any())).thenReturn(formsMock)
        whenever(formsMock.createErrorPage(Response.Status.BAD_REQUEST))
            .thenReturn(Response.status(Response.Status.BAD_REQUEST).build())

        val result = objectUnderTest.result(
            null,
            state,
            "invalid_scope",
            "AUTHCL_0001",
            "https://wiki.gematik.de/pages/viewpage.action?pageId=466488828"
        )

        assertThat(result.statusInfo).isEqualTo(Response.Status.BAD_REQUEST)

        val errorCaptor = argumentCaptor<String>()
        val errorParamCaptor = argumentCaptor<String>()
        verify(formsMock).setError(errorCaptor.capture(), errorParamCaptor.capture())
        assertThat(errorCaptor.firstValue).isEqualTo("authenticator.errorIdp")
        assertThat(errorParamCaptor.firstValue).isEqualTo("AUTHCL_0001")
    }

    private fun assertAuthenticatorUrl(authenticatorUrl: URI, scope: String = "openid Person_ID") {
        assertThat(authenticatorUrl)
            .hasHost("localhost")
            .hasPort(8000)
            .hasPath("/")
        val queryParams = authenticatorUrl.query.split("=", limit = 2)
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

    private fun testResolveAuthSessionFailure(test: () -> Response) {
        whenever(realmMock.getClientByClientId(clientId)).thenReturn(null)
        whenever(callbackMock.error(anyString())).thenReturn(
            Response.status(Response.Status.INTERNAL_SERVER_ERROR).build()
        )

        assertThat(test().statusInfo).isEqualTo(Response.Status.INTERNAL_SERVER_ERROR)

        val errorCaptor = argumentCaptor<String>()
        verify(callbackMock).error(errorCaptor.capture())
        assertThat(errorCaptor.firstValue).isEqualTo("Failed to resolve auth session: client not found or disabled")
    }
}
