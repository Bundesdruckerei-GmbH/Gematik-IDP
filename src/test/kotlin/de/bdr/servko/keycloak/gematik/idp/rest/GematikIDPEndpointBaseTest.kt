/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import com.fasterxml.jackson.databind.ObjectMapper
import de.bdr.servko.keycloak.gematik.idp.TestUtils
import de.bdr.servko.keycloak.gematik.idp.exception.ClientException
import de.bdr.servko.keycloak.gematik.idp.exception.SessionNotFoundException
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPState
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPStatusResponse
import de.bdr.servko.keycloak.gematik.idp.service.GematikIDPService
import de.bdr.servko.keycloak.gematik.idp.token.TestTokenUtil
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals.Companion.AUTHENTICATOR_PORT
import de.bdr.servko.keycloak.gematik.idp.util.RestClient
import de.bdr.servko.keycloak.gematik.idp.validation.GematikIdpCertificateValidatorProvider
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriBuilder
import org.assertj.core.api.Assertions.assertThat
import org.keycloak.OAuth2Constants
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.models.*
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.protocol.oidc.utils.PkceUtils
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.sessions.AuthenticationSessionProvider
import org.keycloak.sessions.RootAuthenticationSessionModel
import org.mockito.ArgumentMatchers
import org.mockito.kotlin.*
import java.net.URI
import java.util.*

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
    val authenticatorVersion = "4.16.0"

    val clientMock = mock<ClientModel> {
        on { isEnabled } doReturn true
        on { clientId } doReturn CLIENT_ID
    }

    val realmMock = mock<RealmModel> {
        on { name } doReturn REALM_NAME
        on { getClientByClientId(CLIENT_ID) } doReturn clientMock
    }

    val callbackMock = mock<UserAuthenticationIdentityProvider.AuthenticationCallback>()

    // Mock the authentication session used by endpoint tests. In addition to the realm and client,
    // we provide the required AUTHENTICATOR_PORT_AUTH_NOTE to avoid repetitive stubbing in each
    // concrete test class (e.g., HbaResourceTest, SmcbResourceTest, MultiResourceTest).
    val authSessionMock = mock<AuthenticationSessionModel> {
        on { realm } doReturn realmMock
        on { client } doReturn clientMock
        on { getAuthNote(AUTHENTICATOR_PORT) } doReturn "80"
    }

    val service = mock<GematikIDPService> {
        on { resolveAuthSessionFromEncodedState(any(), any()) } doReturn authSessionMock
    }

    val certificateValidator = mock<GematikIdpCertificateValidatorProvider> {
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
        on { getProvider(GematikIdpCertificateValidatorProvider::class.java) } doReturn certificateValidator
    }

    val rest = mock<RestClient> {
    }

    val authenticationSession = mock<AuthenticationSessionProvider> {
    }

    val rootAuthenticationSession = mock<RootAuthenticationSessionModel> {
    }

    val formsMock = mock<LoginFormsProvider> {
        on { setError(ArgumentMatchers.anyString(), any()) } doReturn it
        on { setAttribute(ArgumentMatchers.anyString(), any()) } doReturn it
        on { createForm(ArgumentMatchers.anyString()) } doReturn Response.ok().build()
        on { createErrorPage(any()) } doReturn Response.status(Response.Status.BAD_REQUEST).build()
    }

    val config: GematikIDPConfig = GematikIDPConfig().apply {
        alias = IDP_ALIAS
        clientId = GEMATIK_CLIENT_ID
        defaultScope = "openid"
        setOpenidConfigUrl("http://localhost:8000/")
        updateOpenidConfig(TestUtils.discoveryDocument)
        setAuthenticatorAuthorizationUrl(TestUtils.discoveryDocument.authorizationEndpoint)
        setAuthenticatorVersion("4.6.0")
        setTimeoutMs("20000")
        setLoginTimeoutMs("60000")
        setIdpTimeoutMs("10000")
        setIdpUserAgent("Servko/1.0.0 Servko/Client")
        setMultipleIdentityMode(true)
        setAuthenticatorAutoLaunch(true)
        setLoginTimeoutMs("10000")
        isEnabled = true
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

    fun testResolveAuthSessionNotFoundFailure(test: () -> Response) {
        // arrange
        val message = "client not found or disabled"
        whenever(service.resolveAuthSessionFromEncodedState(realmMock, state))
            .thenThrow(SessionNotFoundException(message))
        whenever(callbackMock.error(eq(config), ArgumentMatchers.anyString())).thenReturn(
            Response.status(Response.Status.INTERNAL_SERVER_ERROR).build()
        )

        // act
        assertThat(test().statusInfo).isEqualTo(Response.Status.BAD_REQUEST)

        // assert
        verify(formsMock).setError(eq("loginTimeout"), eq(message))
    }

    fun testResolveAuthSessionNotFoundStatusEndpointFailure(test: () -> Response) {
        // arrange
        val message = "client not found or disabled"
        whenever(service.resolveAuthSessionFromEncodedState(realmMock, state))
            .thenThrow(SessionNotFoundException(message))

        // act
        val response = test()

        // assert
        assertThat(response.statusInfo).isEqualTo(Response.Status.OK)
        val idpStatusResponse = response.entity as GematikIDPStatusResponse
        assertThat(idpStatusResponse.currentStep).isEqualTo("ERROR")
        assertNextStepUrl(idpStatusResponse.nextStepUrl!!)
    }

    fun testResolveAuthSessionFailure(test: () -> Response) {
        // arrange
        val message = "client not found or disabled"
        whenever(service.resolveAuthSessionFromEncodedState(realmMock, state))
            .thenAnswer { _ -> throw ClientException(message) }
        whenever(callbackMock.error(eq(config), ArgumentMatchers.anyString())).thenReturn(
            Response.status(Response.Status.INTERNAL_SERVER_ERROR).build()
        )

        // act & assert
        assertThat(test().statusInfo).isEqualTo(Response.Status.INTERNAL_SERVER_ERROR)
    }

    fun testAssertCodeAndStateNullOrEmpty(test: () -> Response) {
        // act
        val result = test()

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.BAD_REQUEST)
        verify(formsMock).setError("authenticator.errorIdp", "Unknown")
        verify(formsMock).createErrorPage(Response.Status.BAD_REQUEST)
    }

    fun assertNextStepUrl(statusUrl: URI) {
        assertThat(statusUrl)
            .hasHost("localhost")
            .hasPort(8080)
            .hasPath("/realms/test-realm/broker/gematik-idp/endpoint/nextStep")

        val statusUriParams = statusUrl.query.split("&").associate { queryParam ->
            queryParam.split("=").let {
                it[0] to it[1]
            }
        }

        assertThat(statusUriParams[OAuth2Constants.STATE]).isEqualTo(state)
    }

    fun assertAuthenticatorUrl(authenticatorUrl: URI, cardType: String) {
        assertThat(authenticatorUrl).hasNoHost()
        assertThat(authenticatorUrl.toString()).startsWith("authenticator://")
        assertThat(authenticatorUrl.toString()).contains("callback=direct")
        assertChallengePath(authenticatorUrl, cardType)
    }

    private fun assertChallengePath(url: URI, cardType: String) {
        val queryParams = url.query.split("=", "&", limit = 2)
        assertThat(queryParams).hasSize(2)
        assertThat(queryParams[0]).isEqualTo("challenge_path")
        val challengeUri = URI.create(queryParams[1].replace(" ", "%20"))
        assertThat(challengeUri).hasHost("host.docker.internal").hasPort(8081).hasPath("/sign_response")
        val challengeQueryParams = challengeUri.query.split("&").associate { queryParam ->
            queryParam.split("=").let {
                it[0] to it[1]
            }
        }

        assertThat(challengeQueryParams[OAuth2Constants.CLIENT_ID]).isEqualTo(GEMATIK_CLIENT_ID)
        assertThat(challengeQueryParams[OAuth2Constants.RESPONSE_TYPE]).isEqualTo(OAuth2Constants.CODE)
        assertThat(challengeQueryParams[OAuth2Constants.REDIRECT_URI]).isEqualTo(
            "http://localhost:8080/realms/$REALM_NAME/broker/$IDP_ALIAS/endpoint/result")
        assertThat(challengeQueryParams[OAuth2Constants.STATE]).isEqualTo(state)
        assertThat(challengeQueryParams["cardType"]).isEqualTo(cardType)
        assertThat(challengeQueryParams[OAuth2Constants.CODE_CHALLENGE]).isNotBlank
        assertThat(challengeQueryParams[OAuth2Constants.CODE_CHALLENGE_METHOD]).isEqualTo(OAuth2Constants.PKCE_METHOD_S256)
        assertThat(challengeQueryParams[OIDCLoginProtocol.NONCE_PARAM]).isNotBlank
    }

    fun assertAuthorizeUrl(url: URI, cardType: String) {
        assertThat(url).hasScheme("http")
        assertThat(url).hasHost("localhost")
        assertThat(url).hasPort(1234)
        assertChallengePath(url, cardType)
    }

    fun String.decodeBase64(): ByteArray =
        Base64.getDecoder().decode(this)
}
