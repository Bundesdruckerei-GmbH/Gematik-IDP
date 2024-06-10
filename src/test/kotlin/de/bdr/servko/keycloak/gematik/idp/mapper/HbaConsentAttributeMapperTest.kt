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
import de.bdr.servko.keycloak.gematik.idp.model.AuthenticatorClaim
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.models.*
import org.mockito.kotlin.*
import java.time.Instant


internal class HbaConsentAttributeMapperTest {

    private val session: KeycloakSession = mock()
    private val realm: RealmModel = mock()

    private val context  = spy(BrokeredIdentityContext("id"))
    private val mapperModel = IdentityProviderMapperModel().apply {
        config = mapOf(
            AbstractGematikAuthenticatorConsentAttributeMapper.CONFIG_AUTHENTICATOR_CREATED_DATE_ATTRIBUTE to
                    consentCreatedDateAttribute,
            AbstractGematikAuthenticatorConsentAttributeMapper.CONFIG_AUTHENTICATOR_LAST_UPDATED_DATE_ATTRIBUTE to
                    consentLastUpdatedDateAttribute,
        )
    }

    private val consentCreatedDateAttribute = AbstractGematikAuthenticatorConsentAttributeMapper.CONFIG_AUTHENTICATOR_CREATED_DATE_ATTRIBUTE
    private val consentLastUpdatedDateAttribute = AbstractGematikAuthenticatorConsentAttributeMapper.CONFIG_AUTHENTICATOR_LAST_UPDATED_DATE_ATTRIBUTE
    private val createdDateAttribute = AuthenticatorClaim.HBA_CONSENT_CREATED_DATE.scope
    private val lastUpdatedDateAttribute = AuthenticatorClaim.HBA_CONSENT_LAST_UPDATED_DATE.scope

    private val objectUnderTest = HbaConsentAttributeMapper()

    @Test
    fun getConfigProperties() {
        val configProperties = objectUnderTest.configProperties


        assertThat(configProperties).isEmpty()
    }

    @Test
    fun preprocessFederatedIdentity() {
        val closePastTimeValue = Instant.now()
        val createdDateInstantCaptor = argumentCaptor<String>()
        val lastUpdatedDateInstantCaptor = argumentCaptor<String>()


        objectUnderTest.preprocessFederatedIdentity(session, realm, mapperModel, context)


        verify(context)
            .setUserAttribute(
                eq(createdDateAttribute), createdDateInstantCaptor.capture()
            )
        verify(context)
            .setUserAttribute(
                eq(lastUpdatedDateAttribute), lastUpdatedDateInstantCaptor.capture()
            )

        val currentTime = Instant.now()
        assertThat(Instant.parse(createdDateInstantCaptor.firstValue))
            .isBetween(closePastTimeValue, currentTime)
        assertThat(Instant.parse(lastUpdatedDateInstantCaptor.firstValue))
            .isBetween(closePastTimeValue, currentTime)
    }

    @Test
    fun `updateBrokeredUser sets attribute and created_date`() {
        val user: UserModel = mock() {
            on { attributes } doReturn emptyMap()
        }
        val closePastTimeValue = Instant.now()
        val createdDateInstantCaptor = argumentCaptor<String>()


        objectUnderTest.updateBrokeredUser(session, realm, user, mapperModel, context)


        verify(user)
            .setSingleAttribute(eq(createdDateAttribute), createdDateInstantCaptor.capture())

        val currentTime = Instant.now()
        assertThat(Instant.parse(createdDateInstantCaptor.firstValue))
            .isBetween(closePastTimeValue, currentTime)
    }

    @Test
    fun `updateBrokeredUser sets created_date when attribute is empty`() {
        val userAttributes = mapOf(createdDateAttribute to emptyList<String>())
        val user: UserModel = mock() {
            on { attributes } doReturn userAttributes
        }
        val closePastTimeValue = Instant.now()
        val createdDateInstantCaptor = argumentCaptor<String>()


        objectUnderTest.updateBrokeredUser(session, realm, user, mapperModel, context)


        verify(user)
            .setSingleAttribute(eq(createdDateAttribute), createdDateInstantCaptor.capture())

        val currentTime = Instant.now()
        assertThat(Instant.parse(createdDateInstantCaptor.firstValue))
            .isBetween(closePastTimeValue, currentTime)
    }

    @Test
    fun `updateBrokeredUser sets created_date when attribute is null`() {
        val userAttributes = mapOf(createdDateAttribute to null)
        val user: UserModel = mock() {
            on { attributes } doReturn userAttributes
        }
        val closePastTimeValue = Instant.now()
        val createdDateInstantCaptor = argumentCaptor<String>()


        objectUnderTest.updateBrokeredUser(session, realm, user, mapperModel, context)


        verify(user)
            .setSingleAttribute(eq(createdDateAttribute), createdDateInstantCaptor.capture())

        val currentTime = Instant.now()
        assertThat(Instant.parse(createdDateInstantCaptor.firstValue))
            .isBetween(closePastTimeValue, currentTime)
    }

    @Test
    fun `updateBrokeredUser does not update created_date`() {
        val onceUponATime =  Instant.MIN.toString()
        val userAttributes = mapOf(createdDateAttribute to listOf(onceUponATime))
        val user: UserModel = mock() {
            on { attributes } doReturn userAttributes
        }


        objectUnderTest.updateBrokeredUser(session, realm, user, mapperModel, context)


        verify(user, never())
            .setSingleAttribute(eq(createdDateAttribute), any())
    }

    @Test
    fun `updateBrokeredUser sets attribute and last_updated_date`() {
        val user: UserModel = mock() {
            on { attributes } doReturn emptyMap()
        }
        val closePastTimeValue = Instant.now()
        val lastUpdatedDateInstantCaptor = argumentCaptor<String>()


        objectUnderTest.updateBrokeredUser(session, realm, user, mapperModel, context)


        verify(user)
            .setSingleAttribute(eq(lastUpdatedDateAttribute), lastUpdatedDateInstantCaptor.capture())

        val currentTime = Instant.now()
        assertThat(Instant.parse(lastUpdatedDateInstantCaptor.firstValue))
            .isBetween(closePastTimeValue, currentTime)
    }

    @Test
    fun `updateBrokeredUser sets last_updated_date when attribute is empty`() {
        val userAttributes = mapOf(lastUpdatedDateAttribute to emptyList<String>())
        val user: UserModel = mock() {
            on { attributes } doReturn userAttributes
        }
        val closePastTimeValue = Instant.now()
        val lastUpdatedDateInstantCaptor = argumentCaptor<String>()


        objectUnderTest.updateBrokeredUser(session, realm, user, mapperModel, context)


        verify(user)
            .setSingleAttribute(eq(lastUpdatedDateAttribute), lastUpdatedDateInstantCaptor.capture())

        val currentTime = Instant.now()
        assertThat(Instant.parse(lastUpdatedDateInstantCaptor.firstValue))
            .isBetween(closePastTimeValue, currentTime)
    }

    @Test
    fun `updateBrokeredUser sets last_updated_date when attribute is null`() {
        val userAttributes = mapOf(lastUpdatedDateAttribute to null)
        val user: UserModel = mock() {
            on { attributes } doReturn userAttributes
        }
        val closePastTimeValue = Instant.now()
        val lastUpdatedDateInstantCaptor = argumentCaptor<String>()


        objectUnderTest.updateBrokeredUser(session, realm, user, mapperModel, context)


        verify(user)
            .setSingleAttribute(eq(lastUpdatedDateAttribute), lastUpdatedDateInstantCaptor.capture())

        val currentTime = Instant.now()
        assertThat(Instant.parse(lastUpdatedDateInstantCaptor.firstValue))
            .isBetween(closePastTimeValue, currentTime)
    }

    @Test
    fun `updateBrokeredUser updates last_updated_date`() {
        val onceUponATime =  Instant.MIN.toString()
        val userAttributes = mapOf(createdDateAttribute to listOf(onceUponATime))
        val user: UserModel = mock() {
            on { attributes } doReturn userAttributes
        }
        val closePastTimeValue = Instant.now()
        val lastUpdatedDateInstantCaptor = argumentCaptor<String>()


        objectUnderTest.updateBrokeredUser(session, realm, user, mapperModel, context)


        verify(user)
            .setSingleAttribute(eq(lastUpdatedDateAttribute), lastUpdatedDateInstantCaptor.capture())

        val currentTime = Instant.now()
        assertThat(Instant.parse(lastUpdatedDateInstantCaptor.firstValue))
            .isBetween(closePastTimeValue, currentTime)
    }

    @Test
    fun getOperationalInfo() {
        assertThat(objectUnderTest.operationalInfo)
            .extractingByKey("Version")
            .isEqualTo("unknown")
    }

    @Test
    fun getId() {
        assertThat(objectUnderTest.id).isEqualTo("gematik-idp-authenticator-hba-consent-attribute-mapper")
    }

    @Test
    fun getHelpText() {
        assertThat(objectUnderTest.helpText)
            .isEqualTo("Save client consent for HBA from Authenticator, into the specified user attribute.")
    }

    @Test
    fun getDisplayType() {
        assertThat(objectUnderTest.displayType).isEqualTo("Gematik Authenticator HBA Consent Attributes")
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
