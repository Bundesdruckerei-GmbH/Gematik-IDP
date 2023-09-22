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

import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPState
import de.bdr.servko.keycloak.gematik.idp.rest.GematikIDPResource
import de.bdr.servko.keycloak.gematik.idp.util.GematikIDPUtil
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals
import org.keycloak.broker.provider.AbstractIdentityProvider
import org.keycloak.broker.provider.AuthenticationRequest
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.events.EventBuilder
import org.keycloak.models.FederatedIdentityModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import javax.annotation.Generated
import javax.ws.rs.core.Response

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
        callback: IdentityProvider.AuthenticationCallback,
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
