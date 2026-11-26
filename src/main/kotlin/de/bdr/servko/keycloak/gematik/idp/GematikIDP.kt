/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp

import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPState
import de.bdr.servko.keycloak.gematik.idp.rest.GematikIDPResource
import de.bdr.servko.keycloak.gematik.idp.util.GematikIDPUtil
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals
import jakarta.annotation.Generated
import jakarta.ws.rs.core.Response
import org.keycloak.broker.provider.AbstractIdentityProvider
import org.keycloak.broker.provider.AuthenticationRequest
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider
import org.keycloak.common.util.Time
import org.keycloak.events.EventBuilder
import org.keycloak.models.*
import org.keycloak.sessions.AuthenticationSessionModel


class GematikIDP(session: KeycloakSession, config: GematikIDPConfig) :
    AbstractIdentityProvider<GematikIDPConfig>(session, config) {

    /**
     * First call made on login page.
     * Redirect to /callback/startAuth so all requests are handled in
     * [de.bdr.servko.keycloak.gematik.idp.rest.GematikIDPResource]
     */
    override fun performLogin(request: AuthenticationRequest): Response =
        request.authenticationSession.let { authenticationSession ->

            if (validateAndStoreAuthenticatorPort(authenticationSession)) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Invalid authenticatorPort").build()
            }
            storeAuthenticatorHandshakeId(authenticationSession)

            val state = GematikIDPState.fromIdentityBrokerState(
                request.state,
                authenticationSession.parentSession.id
            )
            if (config.getLoginTimeoutMs() > 0) {
                authenticationSession.setAuthNote(
                    GematikIdpLiterals.LOGIN_START_TIME_NOTE,
                    Time.currentTimeMillis().toString()
                )
            }
            Response.seeOther(
                GematikIDPUtil.getEndpointUri(
                    session,
                    authenticationSession.realm,
                    state,
                    config,
                    GematikIdpLiterals.START_AUTH_PATH
                )
            ).build()
        }

    private fun storeAuthenticatorHandshakeId(authenticationSession: AuthenticationSessionModel) {
        // Extract and store the handshake identifier if present. The handshake_id
        // is required by the new‑version authenticator but is optional for legacy
        // flows and for existing tests that may not provide it.
        val handshakeId = session.context.uri.queryParameters
            .getFirst(GematikIdpLiterals.HANDSHAKE_ID)

        if (!handshakeId.isNullOrBlank()) {
            authenticationSession.setAuthNote(
                GematikIdpLiterals.HANDSHAKE_ID,
                handshakeId
            )
        }
    }

    private fun validateAndStoreAuthenticatorPort(authenticationSession: AuthenticationSessionModel): Boolean {
        val authenticatorPort = session.context.uri.queryParameters
            .getFirst(GematikIdpLiterals.AUTHENTICATOR_PORT)

        if (!authenticatorPort.isNullOrBlank()) {
            val port = authenticatorPort.toIntOrNull()

            if (port == null || port !in config.getAuthenticatorPortRangeStart()..config.getAuthenticatorPortRangeEnd()) {
                return true
            }

            authenticationSession.setAuthNote(
                GematikIdpLiterals.AUTHENTICATOR_PORT,
                port.toString()
            )
        }
        return false
    }

    /**
     * All calls to the IDP are handled here, directly
     * forwarded to [de.bdr.servko.keycloak.gematik.idp.rest.GematikIDPResource]
     */
    override fun callback(
        realm: RealmModel,
        callback: UserAuthenticationIdentityProvider.AuthenticationCallback,
        event: EventBuilder,
    ): GematikIDPResource = GematikIDPResource.from(
        realm = realm,
        callback = callback,
        session = session,
        gematikIDP = this,
        config = config,
    )

    @Generated
    override fun retrieveToken(session: KeycloakSession, identity: FederatedIdentityModel): Response =
        Response.ok(identity.token).build()

    @Generated
    override fun retrieveToken(session: KeycloakSession, identity: FederatedIdentityModel, userSesion: UserSessionModel, user: UserModel): Response =
        retrieveToken(session, identity)

}
