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

import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpOpenIDConfigurationService
import de.bdr.servko.keycloak.gematik.idp.util.RestClient
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.entry
import org.junit.jupiter.api.Test
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
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

    private val objectUnderTest = GematikIDPFactory()

    @Test
    fun createAndUpdateConfig() {
        CryptoIntegration.init(javaClass.classLoader)
        objectUnderTest.postInit(null)

        whenever(rest.doGet(any(), any())).thenReturn(mockedOpenidConfig)

        objectUnderTest.createAndUpdateConfig(session, config, clock) {
            object : GematikIdpOpenIDConfigurationService(rest) {
                override fun skipAllValidators(): Boolean = true
            }
        }

        assertThat(config.openidConfig).isEqualTo(TestUtils.discoveryDocument)
    }

    @Test
    fun createAndUpdateConfig_cache() {
        CryptoIntegration.init(javaClass.classLoader)
        objectUnderTest.postInit(null)

        whenever(rest.doGet(any(), eq(userAgent))).thenReturn(mockedOpenidConfig)

        val serviceFactory: (KeycloakSession) -> GematikIdpOpenIDConfigurationService = {
            object : GematikIdpOpenIDConfigurationService(rest) {
                override fun skipAllValidators(): Boolean = true
            }
        }

        objectUnderTest.createAndUpdateConfig(session, config, clock, serviceFactory)
        verify(rest, times(1)).doGet(any(), eq(userAgent))
        objectUnderTest.createAndUpdateConfig(session, config, clock, serviceFactory)
        verify(rest, times(1)).doGet(any(), eq(userAgent))

        assertThat(config.openidConfig).isEqualTo(TestUtils.discoveryDocument)

        //we are in the future +24h and document is expired
        val clock = Clock.fixed(Instant.ofEpochMilli(1667983621000), ZoneId.of("UTC"))
        objectUnderTest.createAndUpdateConfig(session, config, clock, serviceFactory)
        verify(rest, times(2)).doGet(any(), eq(userAgent))
    }

    @Test
    fun createConfig() {
        assertThat(objectUnderTest.createConfig())
            .isInstanceOf(GematikIDPConfig::class.java)
    }

    @Test
    fun getOperationalInfo() {
        assertThat(objectUnderTest.operationalInfo)
            .contains(entry("Version", "unknown"))
    }

    @Test
    fun getId() {
        assertThat(objectUnderTest.id).isEqualTo(GematikIDPFactory.PROVIDER_ID)
    }

    @Test
    fun getName() {
        assertThat(objectUnderTest.name).isEqualTo("Gematik IDP")
    }
}
