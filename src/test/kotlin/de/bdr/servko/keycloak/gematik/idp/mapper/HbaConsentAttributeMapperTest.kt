/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.mapper

import de.bdr.servko.keycloak.gematik.idp.GematikIDPFactory
import de.bdr.servko.keycloak.gematik.idp.model.AuthenticatorClaim
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.models.*
import org.mockito.kotlin.*
import java.time.Instant


internal class HbaConsentAttributeMapperTest {

    private val session: KeycloakSession = mock()
    private val realm: RealmModel = mock()
    private val idpConfig: GematikIDPConfig = mock { on { isEnabled } doReturn true }

    private val context = spy(BrokeredIdentityContext("id", idpConfig))
    private val consentCreatedDateAttribute =
        AbstractGematikAuthenticatorConsentAttributeMapper.CONFIG_AUTHENTICATOR_CREATED_DATE_ATTRIBUTE
    private val consentLastUpdatedDateAttribute =
        AbstractGematikAuthenticatorConsentAttributeMapper.CONFIG_AUTHENTICATOR_LAST_UPDATED_DATE_ATTRIBUTE
    private val mapperModel = IdentityProviderMapperModel().apply {
        config = mapOf(
            AbstractGematikAuthenticatorConsentAttributeMapper.CONFIG_AUTHENTICATOR_CREATED_DATE_ATTRIBUTE to
                    consentCreatedDateAttribute,
            AbstractGematikAuthenticatorConsentAttributeMapper.CONFIG_AUTHENTICATOR_LAST_UPDATED_DATE_ATTRIBUTE to
                    consentLastUpdatedDateAttribute,
        )
    }

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
        val onceUponATime = Instant.MIN.toString()
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
        val onceUponATime = Instant.MIN.toString()
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
