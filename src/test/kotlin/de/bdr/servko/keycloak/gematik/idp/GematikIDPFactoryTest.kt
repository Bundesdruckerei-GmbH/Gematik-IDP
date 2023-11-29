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

package de.bdr.servko.keycloak.gematik.idp

import de.bdr.servko.keycloak.gematik.idp.model.AuthenticationFlowType
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpOpenIDConfigurationService
import de.bdr.servko.keycloak.gematik.idp.util.RestClient
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.entry
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.provider.ProviderConfigProperty
import org.mockito.kotlin.*
import java.time.Clock
import java.time.Instant
import java.time.ZoneId

internal class GematikIDPFactoryTest {

    private val session = mock<KeycloakSession> {
        val keycloakContext = mock<KeycloakContext> { on { realm }.doReturn(mock {}) }
        on { context }.thenReturn(keycloakContext)
    }
    private val configUrl = "http://localhost:8081/.well-known/openid-configuration"
    private val userAgent = "Servko/1.0.0 Servko/Client"
    private val config = GematikIDPConfig().apply {
        setIdpUserAgent(userAgent)
        setOpenidConfigUrl(configUrl)
    }

    private val mockedOpenidConfig =
        javaClass.classLoader.getResourceAsStream("openid-config.txt")?.bufferedReader()?.readText() ?: "error"
    private val clock: Clock = Clock.fixed(Instant.ofEpochMilli(1667981784000), ZoneId.of("UTC"))

    private val rest = mock<RestClient> {}

    private val underTest = GematikIDPFactory()

    @Test
    fun createAndUpdateConfig() {
        CryptoIntegration.init(javaClass.classLoader)
        underTest.postInit(null)

        whenever(rest.doGet(any(), any())).thenReturn(mockedOpenidConfig)

        underTest.createAndUpdateConfig(session, config, clock) {
            object : GematikIdpOpenIDConfigurationService(rest) {
                override fun skipAllValidators(): Boolean = true
            }
        }

        assertThat(config.openidConfig).isEqualTo(TestUtils.discoveryDocument)
    }

    @Test
    fun createAndUpdateConfig_cache() {
        CryptoIntegration.init(javaClass.classLoader)
        underTest.postInit(null)

        whenever(rest.doGet(any(), eq(userAgent))).thenReturn(mockedOpenidConfig)

        val serviceFactory: (KeycloakSession) -> GematikIdpOpenIDConfigurationService = {
            object : GematikIdpOpenIDConfigurationService(rest) {
                override fun skipAllValidators(): Boolean = true
            }
        }

        underTest.createAndUpdateConfig(session, config, clock, serviceFactory)
        verify(rest, times(1)).doGet(any(), eq(userAgent))
        underTest.createAndUpdateConfig(session, config, clock, serviceFactory)
        verify(rest, times(1)).doGet(any(), eq(userAgent))

        assertThat(config.openidConfig).isEqualTo(TestUtils.discoveryDocument)

        //we are in the future +24h and document is expired
        val clock = Clock.fixed(Instant.ofEpochMilli(1667983621000), ZoneId.of("UTC"))
        underTest.createAndUpdateConfig(session, config, clock, serviceFactory)
        verify(rest, times(2)).doGet(any(), eq(userAgent))
    }

    @Test
    fun createConfig() {
        assertThat(underTest.createConfig())
            .isInstanceOf(GematikIDPConfig::class.java)
    }

    @Test
    fun getOperationalInfo() {
        assertThat(underTest.operationalInfo)
            .contains(entry("Version", "unknown"))
    }

    @Test
    fun getId() {
        assertThat(underTest.id).isEqualTo(GematikIDPFactory.PROVIDER_ID)
    }

    @Test
    fun getName() {
        assertThat(underTest.name).isEqualTo("Gematik IDP")
    }

    @Nested
    inner class ConfigPropertiesTest {
        @Test
        fun `configProperties - returns authentication flow config property`() {
            // arrange

            // act
            val result = underTest.configProperties
                .findLast { it.name == "authenticationFlow" }

            // assert
            assertThat(result).isNotNull
            assertThat(result?.label).isEqualTo("Choose Authentication Flow")
            assertThat(result?.helpText).isEqualTo("Choose your preferred authentication flow.")
            assertThat(result?.defaultValue).isEqualTo(AuthenticationFlowType.MULTI.toString())
            assertThat(result?.options).containsExactlyInAnyOrder(
                AuthenticationFlowType.LEGACY.toString(),
                AuthenticationFlowType.MULTI.toString(),
                AuthenticationFlowType.HBA.toString(),
                AuthenticationFlowType.SMCB.toString()
            )
            assertThat(result?.type).isEqualTo(ProviderConfigProperty.LIST_TYPE)
        }

        @Test
        fun `configProperties - returns authenticator authorization url config property`() {
            // arrange

            // act
            val result = underTest.configProperties
                .findLast { it.name == "authenticatorAuthorizationUrl" }

            // assert
            assertThat(result).isNotNull
            assertThat(result?.label).isEqualTo("Authenticator IDP Authorization Url Overwrite")
            assertThat(result?.helpText).isEqualTo("Authorization endpoint of the central IDP, used in the Authenticator. Will be extracted from the openid-configuration when left empty.")
            assertThat(result?.type).isEqualTo(ProviderConfigProperty.STRING_TYPE)
        }

        @Test
        fun `configProperties - returns timeout ms config property`() {
            // arrange

            // act
            val result = underTest.configProperties
                .findLast { it.name == "timeoutMs" }

            // assert
            assertThat(result).isNotNull
            assertThat(result?.label).isEqualTo("Authenticator Timeout (ms)")
            assertThat(result?.helpText).isEqualTo("Timeout in milliseconds until the process of establishing a connection to the Authenticator is aborted (default 20000).")
            assertThat(result?.type).isEqualTo(ProviderConfigProperty.STRING_TYPE)
        }

        @Test
        fun `configProperties - returns openid config url config property`() {
            // arrange

            // act
            val result = underTest.configProperties
                .findLast { it.name == "openidConfigUrl" }

            // assert
            assertThat(result).isNotNull
            assertThat(result?.label).isEqualTo("Gematik IDP openid configuration url")
            assertThat(result?.helpText).isEqualTo("Url to the Gematik IDP discovery document, which is fetched for authorization and token url.")
            assertThat(result?.type).isEqualTo(ProviderConfigProperty.STRING_TYPE)
        }

        @Test
        fun `configProperties - returns idp timeout ms config property`() {
            // arrange

            // act
            val result = underTest.configProperties
                .findLast { it.name == "idpTimeoutMs" }

            // assert
            assertThat(result).isNotNull
            assertThat(result?.label).isEqualTo("Gematik IDP timeout (ms)")
            assertThat(result?.helpText).isEqualTo("Timeout in milliseconds until the process of establishing a connection to the Gematik IDP is aborted (default 10000).")
            assertThat(result?.type).isEqualTo(ProviderConfigProperty.STRING_TYPE)
        }

        @Test
        fun `configProperties - returns idp user agent config property`() {
            // arrange

            // act
            val result = underTest.configProperties
                .findLast { it.name == "idpUserAgent" }

            // assert
            assertThat(result).isNotNull
            assertThat(result?.label).isEqualTo("Gematik IDP User-Agent")
            assertThat(result?.helpText).isEqualTo("User-Agent Header as specified in \"gemILF_PS_eRp - A_20015-01\": <Produktname>/<Produktversion> <Herstellername>/<client_id>")
            assertThat(result?.type).isEqualTo(ProviderConfigProperty.STRING_TYPE)
        }

        @Test
        fun `configProperties - returns multipleIdentityMode config property`() {
            // arrange

            // act
            val result = underTest.configProperties
                .findLast { it.name == "multipleIdentityMode" }

            // assert
            assertThat(result).isNotNull
            assertThat(result?.label).isEqualTo("Multiple Identities Mode")
            assertThat(result?.helpText).isEqualTo("If this option is switched on, the current timestamp is appended to the Gematik-IDP-ID, which means that an eHBA can be linked to several users at the same time.")
            assertThat(result?.type).isEqualTo(ProviderConfigProperty.BOOLEAN_TYPE)
        }
    }
}
