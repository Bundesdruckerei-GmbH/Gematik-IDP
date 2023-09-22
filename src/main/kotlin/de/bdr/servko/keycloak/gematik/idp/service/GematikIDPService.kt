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
import org.jboss.logging.Logger
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.sessions.AuthenticationSessionModel

open class GematikIDPService(private val session: KeycloakSession) {
    private val logger = Logger.getLogger(this::class.java)

    /**
     * @adapted de.bdr.servko.keycloak.gematik.idp.GematikEndpoint.resolveAuthSessionIgnoreCode
     * We resolve the session manually to allow for refreshing the page without being bound by the active
     * session code.
     * We resolve the session using the root session ID in the encoded state, because we don't have a session cookie,
     * when the result endpoint is called by the Gematik-Authenticator
     *
     * @param realm
     * @param encodedState
     * @return
     */
    fun resolveAuthSessionFromEncodedState(
        realm: RealmModel,
        encodedState: String,
    ): AuthenticationSessionModel {
        val state = GematikIDPState.fromEncodedState(encodedState)

        val client = realm.getClientByClientId(state.clientId)
        if (client == null || !client.isEnabled) {
            throw ClientException("client not found or disabled")
        }

        val rootAuthSession = session.authenticationSessions().getRootAuthenticationSession(realm, state.rootSessionId)

        return rootAuthSession.getAuthenticationSession(client, state.tabId) ?: throw authSessionNotFound(encodedState)
    }

    private fun authSessionNotFound(encodedState: String?): SessionNotFoundException {
        val realm = session.context.realm
        logger.error("AuthenticationSessionModel not found for state $encodedState and realm ${realm.name}")
        return SessionNotFoundException("AuthenticationSessionModel not found for state $encodedState")
    }
}
