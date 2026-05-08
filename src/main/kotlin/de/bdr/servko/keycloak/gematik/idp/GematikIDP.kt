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
import org.keycloak.events.EventBuilder
import org.keycloak.models.*


class GematikIDP(session: KeycloakSession, config: GematikIDPConfig) :
    AbstractIdentityProvider<GematikIDPConfig>(session, config) {

    /**
     * First call made on login page.
     * Redirect to /callback/startAuth so all requests are handled in
     * [de.bdr.servko.keycloak.gematik.idp.rest.GematikIDPEndpoint]
     */
    override fun performLogin(request: AuthenticationRequest): Response =
        request.authenticationSession.let {
            val state = GematikIDPState.fromIdentityBrokerState(request.state, it.parentSession.id)

            Response.seeOther(
                GematikIDPUtil.getEndpointUri(
                    session,
                    it.realm,
                    state,
                    config,
                    GematikIdpLiterals.START_AUTH_PATH
                )
            ).build()
        }

    /**
     * All calls to the IDP are handled here, directly
     * forwarded to [de.bdr.servko.keycloak.gematik.idp.rest.GematikIDPEndpoint]
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
}
