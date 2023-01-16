package de.bdr.servko.keycloak.gematik.idp

import org.keycloak.OAuth2Constants
import org.keycloak.broker.provider.AbstractIdentityProvider
import org.keycloak.broker.provider.AuthenticationRequest
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.broker.provider.util.IdentityBrokerState
import org.keycloak.events.EventBuilder
import org.keycloak.models.FederatedIdentityModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.services.resources.IdentityBrokerService
import org.keycloak.services.resources.RealmsResource
import java.net.URI
import javax.annotation.Generated
import javax.ws.rs.core.Response

class GematikIDP(session: KeycloakSession, config: GematikIDPConfig) :
    AbstractIdentityProvider<GematikIDPConfig>(session, config) {

    companion object {
        const val STATE_DELIMITER = "__"
    }

    /**
     * First call made on login page.
     * Redirect to /callback/startAuth so all requests are handled in
     * [de.bdr.servko.keycloak.gematik.idp.GematikIDPEndpoint]
     */
    override fun performLogin(request: AuthenticationRequest): Response =
        request.authenticationSession.let {
            Response.seeOther(
                getEndpointUri(
                    session,
                    it.realm,
                    request.state,
                    config,
                    GematikIDPEndpoint.START_AUTH_PATH
                )
            ).build()
        }

    /**
     * All calls to the IDP are handled here, directly
     * forwarded to [de.bdr.servko.keycloak.gematik.idp.GematikIDPEndpoint]
     */
    override fun callback(
        realm: RealmModel,
        callback: IdentityProvider.AuthenticationCallback,
        event: EventBuilder
    ): GematikIDPEndpoint = GematikIDPEndpoint(realm, callback, session, this, config)

    @Generated
    override fun retrieveToken(session: KeycloakSession, identity: FederatedIdentityModel): Response =
        Response.ok(identity.token).build()

    fun getEndpointUri(
        session: KeycloakSession,
        realm: RealmModel,
        state: IdentityBrokerState?,
        config: GematikIDPConfig,
        endpoint: String
    ): URI =
        RealmsResource.brokerUrl(session.context.uri)
            .path(IdentityBrokerService::class.java, "getEndpoint")
            .path(GematikIDPEndpoint::class.java, endpoint)
            .apply {
                //C-IDP state has pattern ^[_\\-a-zA-Z0-9]{1,32}$
                state?.let {
                    queryParam(OAuth2Constants.STATE, "${it.clientId}$STATE_DELIMITER${it.tabId}")
                }
            }
            .build(realm.name, config.alias)

}
