/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.GematikIDP
import de.bdr.servko.keycloak.gematik.idp.model.AuthenticationFlowType
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import de.bdr.servko.keycloak.gematik.idp.validation.GematikIdpCertificateValidatorProvider
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

internal class GematikIDPResourceTest {

    private val realmMock = mock<RealmModel>()
    private val callbackMock = mock<UserAuthenticationIdentityProvider.AuthenticationCallback>()
    private val certificateValidator = mock<GematikIdpCertificateValidatorProvider>()
    private val sessionMock = mock<KeycloakSession> () {
        on { getProvider(GematikIdpCertificateValidatorProvider::class.java) } doReturn certificateValidator
    }
    private val idp = mock<GematikIDP> ()
    private val formsMock = mock<LoginFormsProvider> ()
    private val config = mock<GematikIDPConfig>()


    @Test
    fun fromConfigWithMultiFlow_ReturnsMultiEndpoint() {
        // arrange
        whenever(config.getAuthenticationFlow()).thenReturn(AuthenticationFlowType.MULTI)

        // act
        val result = GematikIDPResource.from(
            realm = realmMock,
            callback = callbackMock,
            session = sessionMock,
            gematikIDP = idp,
            config = config,
            forms = formsMock,
        )

        // assert
        assertThat(result).isInstanceOf(GematikIDPMultiResource::class.java)
    }

    @Test
    fun fromConfigWithHbaFlow_ReturnsHbaEndpoint() {
        // arrange
        whenever(config.getAuthenticationFlow()).thenReturn(AuthenticationFlowType.HBA)

        // act
        val result = GematikIDPResource.from(
            realm = realmMock,
            callback = callbackMock,
            session = sessionMock,
            gematikIDP = idp,
            config = config,
            forms = formsMock,
        )

        // assert
        assertThat(result).isInstanceOf(GematikIDPHbaResource::class.java)
    }

    @Test
    fun fromConfigWithSmcbFlow_ReturnsSmcbEndpoint() {
        // arrange
        whenever(config.getAuthenticationFlow()).thenReturn(AuthenticationFlowType.SMCB)

        // act
        val result = GematikIDPResource.from(
            realm = realmMock,
            callback = callbackMock,
            session = sessionMock,
            gematikIDP = idp,
            config = config,
            forms = formsMock,
        )

        // assert
        assertThat(result).isInstanceOf(GematikIDPSmcbResource::class.java)
    }

}
