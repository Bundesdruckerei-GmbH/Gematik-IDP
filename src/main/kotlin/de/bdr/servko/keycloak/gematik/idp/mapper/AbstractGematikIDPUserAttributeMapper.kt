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

import de.bdr.servko.keycloak.gematik.idp.CardType
import de.bdr.servko.keycloak.gematik.idp.ContextData
import de.bdr.servko.keycloak.gematik.idp.GematikClaim
import de.bdr.servko.keycloak.gematik.idp.GematikIDPFactory
import org.jboss.logging.Logger
import org.keycloak.broker.provider.AbstractIdentityProviderMapper
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.models.*
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ServerInfoAwareProviderFactory
import java.util.*

abstract class AbstractGematikIDPUserAttributeMapper : AbstractIdentityProviderMapper(), ServerInfoAwareProviderFactory {

    private val logger = Logger.getLogger(this::class.java)

    companion object {
        const val CONFIG_USER_ATTRIBUTE = "userAttribute"
        const val CONFIG_CLAIM_ATTRIBUTE = "claimAttribute"
    }

    abstract val cardType: CardType

    private val supportedSyncModes = listOf(IdentityProviderSyncMode.IMPORT, IdentityProviderSyncMode.FORCE)

    override fun getConfigProperties(): List<ProviderConfigProperty> =
        listOf(
            ProviderConfigProperty(
                CONFIG_USER_ATTRIBUTE,
                "User Attribute Name",
                "User attribute name to store information into.",
                ProviderConfigProperty.STRING_TYPE,
                null
            ),
            ProviderConfigProperty(
                CONFIG_CLAIM_ATTRIBUTE,
                "Gematik Claim",
                "Gematik claim to read data from",
                ProviderConfigProperty.LIST_TYPE,
                null,
                *ContextData.values().filter {
                    it.cardType == cardType
                }.map { it.claim.name }.toTypedArray()
            )
        )

    override fun getCompatibleProviders(): Array<String> = arrayOf(GematikIDPFactory.PROVIDER_ID)

    override fun getDisplayCategory(): String = "Attribute Importer"

    override fun supportsSyncMode(syncMode: IdentityProviderSyncMode): Boolean =
        supportedSyncModes.contains(syncMode)

    override fun preprocessFederatedIdentity(
        session: KeycloakSession?,
        realm: RealmModel?,
        mapperModel: IdentityProviderMapperModel,
        context: BrokeredIdentityContext
    ) {
        getAttributeName(mapperModel)
            ?.let { attributeName ->
                getValue(mapperModel, context)?.let {
                    context.setUserAttribute(attributeName, it)
                }
            }
    }

    override fun updateBrokeredUser(
        session: KeycloakSession?,
        realm: RealmModel?,
        user: UserModel,
        mapperModel: IdentityProviderMapperModel,
        context: BrokeredIdentityContext
    ) {
        getAttributeName(mapperModel)
            ?.let { attributeName ->
                getValue(mapperModel, context)?.let {
                    user.setSingleAttribute(attributeName, it)
                } ?: user.removeAttribute(attributeName)
            }
    }


    fun getValue(mapperModel: IdentityProviderMapperModel, context: BrokeredIdentityContext): String? =
        mapperModel.config[CONFIG_CLAIM_ATTRIBUTE]?.let {
            GematikClaim.valueOf(it)
        }?.let { claim ->
            getContextData(claim)?.let {
                context.contextData[it.name] as? String
            }
        }

    private fun getContextData(claim: GematikClaim): ContextData? =
        ContextData.values().firstOrNull { it.cardType == cardType && it.claim == claim }

    private fun getAttributeName(mapperModel: IdentityProviderMapperModel): String? =
        mapperModel.config[CONFIG_USER_ATTRIBUTE]?.trim()
            ?.takeIf {
                it.isNotEmpty()
            } ?: kotlin.run {
            logger.warnf(
                "Attribute is not configured for mapper %s",
                mapperModel.name
            )
            null
        }

    override fun getOperationalInfo(): Map<String, String> =
        javaClass
            .getResourceAsStream("/META-INF/maven/de.bdr.servko/gematik-idp/pom.properties")
            ?.let {
                val prop = Properties()
                try {
                    prop.load(it)
                } catch (e: Exception) {
                    //ignore
                }
                mapOf("Version" to prop.getProperty("version", "unknown"))
            } ?: mapOf("Version" to "unknown")

}
