/*
 *  Copyright 2025 Bundesdruckerei GmbH and/or its affiliates
 *  and other contributors.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

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
