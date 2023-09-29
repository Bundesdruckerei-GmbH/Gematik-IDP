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

package de.bdr.servko.keycloak.gematik.idp.service

import de.bdr.servko.keycloak.gematik.idp.exception.ClientException
import de.bdr.servko.keycloak.gematik.idp.exception.SessionNotFoundException
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPState
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.sessions.AuthenticationSessionProvider
import org.keycloak.sessions.RootAuthenticationSessionModel
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

internal class GematikIDPServiceTest {
    private val realmName = "test-realm"
    private val clientId = "gematik_client"
    private val rootSessionId = "root-session"
    private val tabId = "tabId"
    private val state: String = GematikIDPState(rootSessionId, clientId, tabId).encode()

    private val clientMock = mock<ClientModel> {
        on { isEnabled } doReturn true
        on { clientId } doReturn clientId
    }
    private val realmMock = mock<RealmModel> {
        on { name } doReturn realmName
    }

    private val authSessionMock = mock<AuthenticationSessionModel> {}
    private val rootAuthSessionMock = mock<RootAuthenticationSessionModel> {
        on { getAuthenticationSession(clientMock, tabId) } doReturn authSessionMock
    }

    private val authSessionProvider = mock<AuthenticationSessionProvider> {
        on { getRootAuthenticationSession(realmMock, rootSessionId) } doReturn rootAuthSessionMock
    }

    private val sessionMock = mock<KeycloakSession> {
        val keycloakContext = mock<KeycloakContext> {
            on { realm } doAnswer { realmMock }
        }
        on { context } doReturn keycloakContext
        on { authenticationSessions() } doReturn authSessionProvider
    }

    private val underTest = GematikIDPService(sessionMock)

    @Test
    fun authSessionFoundThroughSessionManager() {
        // arrange
        whenever(realmMock.getClientByClientId(clientId)).thenReturn(clientMock)

        // act
        val result = underTest.resolveAuthSessionFromEncodedState(realmMock, state)

        // assert
        assertThat(result).isEqualTo(authSessionMock)
    }

    @Test
    fun authSessionNotFound() {
        // arrange
        whenever(sessionMock.authenticationSessions()).thenReturn(authSessionProvider)
        whenever(authSessionProvider.getRootAuthenticationSession(realmMock, rootSessionId)).thenReturn(rootAuthSessionMock)
        whenever(rootAuthSessionMock.getAuthenticationSession(clientMock, tabId)).thenReturn(null)
        whenever(realmMock.getClientByClientId(clientId)).thenReturn(clientMock)

        // act + assert
        assertThatThrownBy {
            underTest.resolveAuthSessionFromEncodedState(realmMock, state)
        }.isInstanceOf(SessionNotFoundException::class.java)
    }

    @Test
    fun clientNotFound() {
        // arrange
        whenever(realmMock.getClientByClientId(clientId)).thenReturn(null)

        // act + assert
        assertThatThrownBy {
            underTest.resolveAuthSessionFromEncodedState(realmMock, state)
        }.isInstanceOf(ClientException::class.java).hasMessage("client not found or disabled")
    }
}
