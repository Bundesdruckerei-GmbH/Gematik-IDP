package de.bdr.servko.keycloak.gematik.idp.model

import org.keycloak.broker.provider.util.IdentityBrokerState

class GematikIDPState(
    val rootSessionId: String,
    val clientId: String,
    val tabId: String
) {
    companion object {
        const val STATE_DELIMITER = "__"

        fun fromIdentityBrokerState(identityBrokerState: IdentityBrokerState, rootSessionId: String) =
            GematikIDPState(rootSessionId, identityBrokerState.clientId, identityBrokerState.tabId)

        fun fromEncodedState(encodedState: String) =
            encodedState.split(STATE_DELIMITER).takeIf {
                it.size == 3
            }?.let {
                GematikIDPState(it.component1(), it.component2(), it.component3());
            } ?: throw Exception("invalid state $encodedState")
    }

    fun encode() = "${rootSessionId}$STATE_DELIMITER${clientId}$STATE_DELIMITER${tabId}"
}
