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

package de.bdr.servko.keycloak.gematik.idp.mapper

import de.bdr.servko.keycloak.gematik.idp.model.AuthenticatorClaim
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.models.IdentityProviderMapperModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.provider.ProviderConfigProperty
import java.time.Instant

abstract class AbstractGematikAuthenticatorConsentAttributeMapper : AbstractGematikIDPUserAttributeMapper() {

    companion object {
        const val CONFIG_AUTHENTICATOR_CREATED_DATE_ATTRIBUTE = "consentCreatedDateAttribute"
        const val CONFIG_AUTHENTICATOR_LAST_UPDATED_DATE_ATTRIBUTE = "consentLastUpdatedDateAttribute"
    }

    private val consentCreatedDateClaim = AuthenticatorClaim.entries
        .first { it.cardType == cardType && it.name.contains("CREATED")  }
    private val consentLastUpdatedDateClaim = AuthenticatorClaim.entries
        .first { it.cardType == cardType && it.name.contains("UPDATED") }

    override fun getConfigProperties(): List<ProviderConfigProperty> = emptyList<ProviderConfigProperty>()

    override fun preprocessFederatedIdentity(
        session: KeycloakSession?,
        realm: RealmModel?,
        mapperModel: IdentityProviderMapperModel,
        context: BrokeredIdentityContext
    ) {
        context.setUserAttribute(consentCreatedDateClaim.scope, Instant.now().toString())
        context.setUserAttribute(consentLastUpdatedDateClaim.scope, Instant.now().toString())
    }

    override fun updateBrokeredUser(
        session: KeycloakSession?,
        realm: RealmModel?,
        user: UserModel,
        mapperModel: IdentityProviderMapperModel,
        context: BrokeredIdentityContext
    ) {
        setConsentCreatedDate(user)
        setConsentLastUpdatedDate(user)
    }

    private fun setConsentCreatedDate(user: UserModel) {
        if (user.attributes[consentCreatedDateClaim.scope].isNullOrEmpty()) {
            user.setSingleAttribute(consentCreatedDateClaim.scope, Instant.now().toString())
        }
    }

    private fun setConsentLastUpdatedDate(user: UserModel) {
        user.setSingleAttribute(consentLastUpdatedDateClaim.scope, Instant.now().toString())
    }

}
