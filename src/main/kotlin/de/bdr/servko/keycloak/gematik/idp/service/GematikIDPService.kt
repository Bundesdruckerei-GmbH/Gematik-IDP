/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
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

        return rootAuthSession?.getAuthenticationSession(client, state.tabId) ?: throw authSessionNotFound(encodedState)
    }

    private fun authSessionNotFound(encodedState: String?): SessionNotFoundException {
        val realm = session.context.realm
        logger.warn("AuthenticationSessionModel not found for state $encodedState and realm ${realm.name}")
        return SessionNotFoundException("AuthenticationSessionModel not found for state $encodedState")
    }
}
