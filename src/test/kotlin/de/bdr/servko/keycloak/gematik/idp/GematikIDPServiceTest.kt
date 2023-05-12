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

import de.bdr.servko.keycloak.gematik.idp.exception.SessionNotFoundException
import de.bdr.servko.keycloak.gematik.idp.extension.AuthenticationSessionAdapterExtension
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.services.managers.AuthenticationSessionManager
import org.keycloak.sessions.AuthenticationSessionModel
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

internal class GematikIDPServiceTest {
    private val realmName = "test-realm"
    private val clientId = "gematik_client"
    private val state: String = "$clientId${GematikIDP.STATE_DELIMITER}tabId"

    private val clientMock = mock<ClientModel> {
        on { isEnabled } doReturn true
        on { clientId } doReturn clientId
    }
    private val realmMock = mock<RealmModel> {
        on { name } doReturn realmName
        on { getClientByClientId(clientId) } doReturn clientMock
    }

    private val authenticationSessionManagerMock = mock<AuthenticationSessionManager> {}

    private val authenticationSessionAdapterExtensionMock = mock<AuthenticationSessionAdapterExtension> {}

    private val authSessionMock = mock<AuthenticationSessionModel> {}

    private val sessionMock = mock<KeycloakSession> {
        val keycloakContext = mock<KeycloakContext> {
            on { realm } doAnswer { realmMock }
        }
        on { context } doReturn keycloakContext
    }

    private val underTest =
        GematikIDPService(sessionMock, authenticationSessionManagerMock, authenticationSessionAdapterExtensionMock)

    @Test
    fun authSessionFoundThroughSessionManager() {
        // arrange
        whenever(authenticationSessionManagerMock.getCurrentAuthenticationSession(realmMock, clientMock, "tabId"))
            .thenReturn(authSessionMock)

        // act
        val result = underTest.resolveAuthSessionFromEncodedState(realmMock, state)

        // assert
        assertThat(result).isEqualTo(authSessionMock)
    }

    @Test
    fun authSessionFoundThroughSessionExtensionViaCache() {
        // arrange
        whenever(authenticationSessionManagerMock.getCurrentAuthenticationSession(realmMock, clientMock, "tabId"))
            .thenReturn(null)
        whenever(authenticationSessionAdapterExtensionMock.getAuthenticationSessionFor("tabId", clientMock))
            .thenReturn(authSessionMock)

        // act
        val result = underTest.resolveAuthSessionFromEncodedState(realmMock, state)

        // assert
        assertThat(result).isEqualTo(authSessionMock)
    }

    @Test
    fun authSessionNotFound() {
        // arrange
        whenever(authenticationSessionManagerMock.getCurrentAuthenticationSession(realmMock, clientMock, "tabId"))
            .thenReturn(null)
        whenever(authenticationSessionAdapterExtensionMock.getAuthenticationSessionFor("tabId", clientMock))
            .thenReturn(null)

        // act + assert
        assertThrows<SessionNotFoundException> {
            underTest.resolveAuthSessionFromEncodedState(realmMock, state)
        }
    }
}
