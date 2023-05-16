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

package de.bdr.servko.keycloak.gematik.idp.mapper

import de.bdr.servko.keycloak.gematik.idp.GematikIDPFactory
import de.bdr.servko.keycloak.gematik.idp.model.ContextData
import de.bdr.servko.keycloak.gematik.idp.model.GematikClaim
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.models.*
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify


internal class HbaUserAttributeMapperTest {

    private val session: KeycloakSession = mock()

    private val realm: RealmModel = mock()

    private val objectUnderTest = HbaUserAttributeMapper()

    private lateinit var mapperModel: IdentityProviderMapperModel
    private lateinit var context: BrokeredIdentityContext

    private val userAttribute = "hba.telematik_id"
    private val smcbValue = "telematik_id"

    @BeforeEach
    fun setup() {
        mapperModel = IdentityProviderMapperModel().apply {
            config = mapOf(
                AbstractGematikIDPUserAttributeMapper.CONFIG_USER_ATTRIBUTE to userAttribute,
                AbstractGematikIDPUserAttributeMapper.CONFIG_CLAIM_ATTRIBUTE to GematikClaim.TELEMATIK_ID.name
            )
        }
        context = BrokeredIdentityContext("id").apply {
            contextData[ContextData.CONTEXT_HBA_TELEMATIK_ID.name] = smcbValue
        }
    }

    @Test
    fun getConfigProperties() {
        val configProperties = objectUnderTest.configProperties
        assertThat(configProperties).hasSize(2)
        val claimAttribute = configProperties[1]
        assertThat(claimAttribute.options).hasSize(4)
            .containsExactly(
                GematikClaim.TELEMATIK_ID.name,
                GematikClaim.PROFESSION_OID.name,
                GematikClaim.FAMILY_NAME.name,
                GematikClaim.GIVEN_NAME.name,
            )
    }

    @Test
    fun preprocessFederatedIdentity() {
        objectUnderTest.preprocessFederatedIdentity(session, realm, mapperModel, context)

        assertThat(context.getUserAttribute(userAttribute)).isEqualTo(smcbValue)
    }

    @Test
    fun preprocessFederatedIdentity_userAttributeNotDefined() {
        mapperModel.config = mutableMapOf()
        objectUnderTest.preprocessFederatedIdentity(session, realm, mapperModel, context)

        assertThat(context.getUserAttribute(userAttribute)).isNullOrEmpty()
    }

    @Test
    fun updateBrokeredUser_addAttribute() {
        val user: UserModel = mock()
        objectUnderTest.updateBrokeredUser(session, realm, user, mapperModel, context)

        verify(user).setSingleAttribute(userAttribute, smcbValue)
        verify(user, never()).removeAttribute(userAttribute)
    }

    @Test
    fun updateBrokeredUser_removeAttribute() {
        val user: UserModel = mock()
        context.contextData[ContextData.CONTEXT_HBA_TELEMATIK_ID.name] = null

        objectUnderTest.updateBrokeredUser(session, realm, user, mapperModel, context)

        verify(user, never()).setSingleAttribute(userAttribute, smcbValue)
        verify(user).removeAttribute(userAttribute)
    }

    @Test
    fun getOperationalInfo() {
        assertThat(objectUnderTest.operationalInfo)
            .extractingByKey("Version")
            .isEqualTo("unknown")
    }

    @Test
    fun getId() {
        assertThat(objectUnderTest.id).isEqualTo("gematik-idp-hba-user-mapper")
    }

    @Test
    fun getHelpText() {
        assertThat(objectUnderTest.helpText).isEqualTo("Import the claim of the HBA card, if it exists, into the specified user attribute.")
    }

    @Test
    fun getDisplayType() {
        assertThat(objectUnderTest.displayType).isEqualTo("Gematik HBA Claim Attribute")
    }

    @Test
    fun getCompatibleProviders() {
        assertThat(objectUnderTest.compatibleProviders).containsOnly(GematikIDPFactory.PROVIDER_ID)
    }

    @Test
    fun getDisplayCategory() {
        assertThat(objectUnderTest.displayCategory).isEqualTo("Attribute Importer")
    }

    @Test
    fun supportsSyncMode() {
        assertThat(objectUnderTest.supportsSyncMode(IdentityProviderSyncMode.IMPORT)).isTrue
        assertThat(objectUnderTest.supportsSyncMode(IdentityProviderSyncMode.FORCE)).isTrue
        assertThat(objectUnderTest.supportsSyncMode(IdentityProviderSyncMode.LEGACY)).isFalse
    }
}
