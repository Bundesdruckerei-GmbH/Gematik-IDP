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
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package de.bdr.servko.keycloak.gematik.idp.extension

import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.sessions.infinispan.InfinispanAuthenticationSessionProvider
import org.keycloak.models.sessions.infinispan.InfinispanAuthenticationSessionProviderFactory
import org.keycloak.models.sessions.infinispan.RootAuthenticationSessionAdapter
import org.keycloak.models.sessions.infinispan.entities.RootAuthenticationSessionEntity
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.sessions.AuthenticationSessionProvider

/**
 * This is an extension to the normal session retrieving functions of Keycloak. It directly loads specific session from
 * the InfiniSpan cache. This is necessary, because we don't have the ID of the Root Authentication Session, when our
 * plugin is called by the Gematik-Authenticator, because it only sends the client-ID tab-ID combination set in the
 * state query parameter.
 *
 * @property session
 * @property realm
 */
class AuthenticationSessionAdapterExtension(
    private val session: KeycloakSession,
    private val realm: RealmModel
) {
    fun getAuthenticationSessionFor(
        tabId: String,
        client: ClientModel,
    ): AuthenticationSessionModel? {
        val infinispanAuthenticationSessionProvider =
            session.getProvider(AuthenticationSessionProvider::class.java) as InfinispanAuthenticationSessionProvider
        val rootAuthenticationSessionEntity: RootAuthenticationSessionEntity? = infinispanAuthenticationSessionProvider
            .cache.values
            .find { rootAuthenticationSessionEntity ->
                rootAuthenticationSessionEntity.authenticationSessions
                    .containsKey(tabId)
            }

        return RootAuthenticationSessionAdapter(
            session,
            infinispanAuthenticationSessionProvider,
            infinispanAuthenticationSessionProvider.cache,
            realm,
            rootAuthenticationSessionEntity,
            InfinispanAuthenticationSessionProviderFactory.DEFAULT_AUTH_SESSIONS_LIMIT
        ).getAuthenticationSession(client, tabId)
    }
}
