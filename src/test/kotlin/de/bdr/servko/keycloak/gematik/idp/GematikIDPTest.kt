/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp

import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPState
import de.bdr.servko.keycloak.gematik.idp.rest.GematikIDPResource
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals
import de.bdr.servko.keycloak.gematik.idp.validation.GematikIdpCertificateValidatorProvider
import jakarta.ws.rs.core.MultivaluedMap
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriBuilder
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.NullSource
import org.keycloak.broker.provider.AbstractIdentityProvider.BROKER_REGISTERED_NEW_USER
import org.keycloak.broker.provider.AbstractIdentityProvider.UPDATE_PROFILE_EMAIL_CHANGED
import org.keycloak.broker.provider.AuthenticationRequest
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider
import org.keycloak.broker.provider.util.IdentityBrokerState
import org.keycloak.events.EventBuilder
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.models.*
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.sessions.AuthenticationSessionProvider
import org.keycloak.sessions.RootAuthenticationSessionModel
import org.mockito.ArgumentMatchers.anyString
import org.mockito.kotlin.*
import java.net.URI
import java.util.*

internal class GematikIDPTest {
    private val realmName = "test-realm"
    private val idpAlias = "gematik-idp"
    private val rootSessionId = "root-session"
    private val clientId = "gematik_client"
    private val tabId = "tabId"
    private val clientData = "clientData"
    private val state = GematikIDPState(rootSessionId, clientId, tabId).encode()

    private val config: GematikIDPConfig = GematikIDPConfig().apply {
        alias = idpAlias
        syncMode = IdentityProviderSyncMode.FORCE
    }
    private val realm = mock<RealmModel> {
        on { name } doReturn realmName
    }
    private val user = mock<UserModel> {
        on { email } doReturn "test-user@gematik.de"
    }

    private val rootAuthSessionMock: RootAuthenticationSessionModel = mock<RootAuthenticationSessionModel> {
        on { id } doReturn rootSessionId
    }
    private val authSession = mock<AuthenticationSessionModel> {
        on { realm } doReturn realm
        on { parentSession } doReturn rootAuthSessionMock
    }
    private val authSessionProvider = mock<AuthenticationSessionProvider> {
        on { getRootAuthenticationSession(realm, rootSessionId) } doReturn rootAuthSessionMock
    }
    private val request = mock<AuthenticationRequest> {
        on { authenticationSession } doReturn authSession
        on { state } doReturn
                IdentityBrokerState.decoded(
                    UUID.randomUUID().toString(), null, clientId, tabId, clientData
                )
    }

    private val queryParamsMock = mock<MultivaluedMap<String, String>> {
        on { getFirst(GematikIdpLiterals.AUTHENTICATOR_PORT) } doReturn "8083"
        on { getFirst(GematikIdpLiterals.HANDSHAKE_ID) } doReturn "4dg578hs"
        on { getFirst(GematikIdpLiterals.AUTHENTICATOR_VERSION_PARAM) } doReturn "4.17.1"
    }

    private val keycloakUriInfo = mock<KeycloakUriInfo> {
        // Provide a base URI builder for constructing redirect URLs
        on { baseUriBuilder } doReturn UriBuilder.fromUri("http://localhost:8080")
        // Ensure queryParameters is non‑null to avoid NPE in performLogin.
        on { queryParameters } doReturn queryParamsMock
    }
    private val keycloakContext = mock<KeycloakContext> {
        on { uri } doReturn keycloakUriInfo
        on { realm } doReturn realm
    }
    private val session = mock<KeycloakSession> {
        on { context } doReturn keycloakContext
        on { authenticationSessions() } doReturn authSessionProvider
    }
    private val objectUnderTest: GematikIDP = GematikIDP(session, config)

    @Test
    fun performLogin() {
        val performLogin = objectUnderTest.performLogin(request)
        assertThat(performLogin.status).isEqualTo(Response.Status.SEE_OTHER.statusCode)
        assertThat(performLogin.location).isEqualTo(URI.create("http://localhost:8080/realms/$realmName/broker/$idpAlias/endpoint/startAuth?state=$state"))
        // Verify that the authenticatorPort auth note was set correctly.
        verify(authSession).setAuthNote(
            GematikIdpLiterals.AUTHENTICATOR_PORT,
            "8083"
        )
        verify(authSession).setAuthNote(
            GematikIdpLiterals.HANDSHAKE_ID,
            "4dg578hs"
        )
    }

    @Test
    fun `performLogin() succeeds without handshake id and authenticator version`() {
        val queryParamsMockMinimal = mock<MultivaluedMap<String, String>> {
            on { getFirst(GematikIdpLiterals.AUTHENTICATOR_PORT) } doReturn "8083"
            on { getFirst(GematikIdpLiterals.HANDSHAKE_ID) } doReturn ""
            on { getFirst(GematikIdpLiterals.AUTHENTICATOR_VERSION_PARAM) } doReturn ""
        }
        val keycloakUriInfoMinimal = mock<KeycloakUriInfo> {
            // Provide a base URI builder for constructing redirect URLs
            on { baseUriBuilder } doReturn UriBuilder.fromUri("http://localhost:8080")
            // Ensure queryParameters is non‑null to avoid NPE in performLogin.
            on { queryParameters } doReturn queryParamsMockMinimal
        }
        val keycloakContextMinimal = mock<KeycloakContext> {
            on { uri } doReturn keycloakUriInfoMinimal
            on { realm } doReturn realm
        }
        val sessionMinimal = mock<KeycloakSession> {
            on { context } doReturn keycloakContextMinimal
            on { authenticationSessions() } doReturn authSessionProvider
        }
        val objectUnderTestMinimal = GematikIDP(sessionMinimal, config)
        val performLogin = objectUnderTestMinimal.performLogin(request)
        assertThat(performLogin.status).isEqualTo(Response.Status.SEE_OTHER.statusCode)
        assertThat(performLogin.location).isEqualTo(URI.create("http://localhost:8080/realms/$realmName/broker/$idpAlias/endpoint/startAuth?state=$state"))
        // Verify that the authenticatorPort auth note was set correctly.
        verify(authSession).setAuthNote(
            GematikIdpLiterals.AUTHENTICATOR_PORT,
            "8083"
        )
        verify(authSession, never())
            .setAuthNote(eq(GematikIdpLiterals.HANDSHAKE_ID), anyString())
        verify(authSession, never())
            .setAuthNote(eq(GematikIdpLiterals.AUTHENTICATOR_VERSION), anyString())
    }

    @Test
    fun `performLogin returns BAD_REQUEST for invalid authenticatorPort`() {
        // Setup a request where the authenticatorPort parameter is invalid (non‑numeric).
        val invalidQueryParams = mock<MultivaluedMap<String, String>> {
            on { getFirst(GematikIdpLiterals.AUTHENTICATOR_PORT) } doReturn "notANumber"
        }
        // For the invalid case we need a separate authentication session mock to avoid interference with the
        // happy‑path verification that already called `setAuthNote` on `authSession`.
        val authSessionInvalid = mock<AuthenticationSessionModel> {
            on { realm } doReturn realm
            on { parentSession } doReturn rootAuthSessionMock
        }
        val requestInvalid = mock<AuthenticationRequest> {
            on { authenticationSession } doReturn authSessionInvalid
            on { state } doReturn IdentityBrokerState.decoded(
                UUID.randomUUID().toString(), null, clientId, tabId, clientData
            )
        }
        val invalidKeycloakUriInfo = mock<KeycloakUriInfo> {
            on { baseUriBuilder } doReturn UriBuilder.fromUri("http://localhost:8080")
            on { queryParameters } doReturn invalidQueryParams
        }
        val invalidKeycloakContext = mock<KeycloakContext> {
            on { uri } doReturn invalidKeycloakUriInfo
            on { realm } doReturn realm
        }
        val invalidSession = mock<KeycloakSession> {
            on { context } doReturn invalidKeycloakContext
            on { authenticationSessions() } doReturn authSessionProvider
        }
        val underTest = GematikIDP(invalidSession, config)

        // Act
        val response = underTest.performLogin(requestInvalid)

        //Assert
        assertThat(response.status).isEqualTo(Response.Status.BAD_REQUEST.statusCode)
        assertThat(response.entity).isEqualTo("Invalid authenticatorPort")
        // No auth note should be set for the invalid case.
        verify(authSessionInvalid, never()).setAuthNote(eq(GematikIdpLiterals.AUTHENTICATOR_PORT), any())
        // No additional auth note should be set for the invalid case (the existing mock records only the happy‑path interaction).
    }

    @Test
    fun callback() {
        val certificateValidator = mock<GematikIdpCertificateValidatorProvider>()
        val formsProvider = mock<LoginFormsProvider>()
        whenever(session.getProvider(GematikIdpCertificateValidatorProvider::class.java)).thenReturn(
            certificateValidator
        )
        whenever(session.getProvider(LoginFormsProvider::class.java)).thenReturn(formsProvider)
        val authenticationCallback = mock<UserAuthenticationIdentityProvider.AuthenticationCallback>()
        val eventBuilder = mock<EventBuilder>()

        assertThat(objectUnderTest.callback(realm, authenticationCallback, eventBuilder))
            .isInstanceOf(GematikIDPResource::class.java)
    }

    @Test
    fun `should update email when federatedEmail is not null`() {
        // arrange
        val federatedEmail = "federated-email@gematik.de"

        val idpConfig = mock<IdentityProviderModel>()
        whenever(idpConfig.isTrustEmail).thenReturn(false)

        val brokerAuthSession = mock<AuthenticationSessionModel>()
        whenever(brokerAuthSession.getAuthNote(BROKER_REGISTERED_NEW_USER)).thenReturn("false")
        whenever(brokerAuthSession.getAuthNote(UPDATE_PROFILE_EMAIL_CHANGED)).thenReturn("false")

        val brokeredIdentityContext = mock<BrokeredIdentityContext>()
        whenever(brokeredIdentityContext.authenticationSession).thenReturn(brokerAuthSession)
        whenever(brokeredIdentityContext.idpConfig).thenReturn(idpConfig)
        whenever(brokeredIdentityContext.email).thenReturn(federatedEmail)

        objectUnderTest.updateBrokeredUser(session, realm, user, brokeredIdentityContext)

        // Verify that email was updated
        verify(user).email = federatedEmail
    }

    @ParameterizedTest(name = "should not update email when federatedEmail is null")
    @NullSource
    fun `should not update email when federatedEmail is null `(federatedEmail: String?) {
        // arrange
        val idpConfig = mock<IdentityProviderModel>()
        whenever(idpConfig.isTrustEmail).thenReturn(false)

        val brokerAuthSession = mock<AuthenticationSessionModel>()
        whenever(brokerAuthSession.getAuthNote(BROKER_REGISTERED_NEW_USER)).thenReturn("false")
        whenever(brokerAuthSession.getAuthNote(UPDATE_PROFILE_EMAIL_CHANGED)).thenReturn("false")

        val brokeredIdentityContext = mock<BrokeredIdentityContext>()
        whenever(brokeredIdentityContext.authenticationSession).thenReturn(brokerAuthSession)
        whenever(brokeredIdentityContext.idpConfig).thenReturn(idpConfig)
        whenever(brokeredIdentityContext.email).thenReturn(federatedEmail)

        objectUnderTest.updateBrokeredUser(session, realm, user, brokeredIdentityContext)

        // Verify that email was never updated
        verify(user, never()).email = anyString()
    }
}
