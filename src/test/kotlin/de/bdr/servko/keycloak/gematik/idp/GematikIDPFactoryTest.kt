package de.bdr.servko.keycloak.gematik.idp

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.entry
import org.junit.jupiter.api.Test
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.models.KeycloakSession
import org.mockito.kotlin.mock
import java.time.Clock
import java.time.Instant
import java.time.ZoneId

internal class GematikIDPFactoryTest {

    private val session = mock<KeycloakSession>()
    private val configUrl = "http://localhost:8081/.well-known/openid-configuration"
    private val userAgent = "Servko/1.0.0 Servko/Client"
    private val config = GematikIDPConfig().apply {
        setIdpUserAgent(userAgent)
        setOpenidConfigUrl(configUrl)
    }

    private val mockedOpenidConfig =
        javaClass.classLoader.getResourceAsStream("openid-config.txt")?.bufferedReader()?.readText() ?: "error"
    private val clock: Clock = Clock.fixed(Instant.ofEpochMilli(1667981784000), ZoneId.of("UTC"))

    private val objectUnderTest = GematikIDPFactory()

    @Test
    fun createAndUpdateConfig() {
        CryptoIntegration.init(javaClass.classLoader)
        objectUnderTest.postInit(null)

        objectUnderTest.createAndUpdateConfig(session, config, clock) {
            object : GematikIDPService(it) {
                override fun doGet(idpUrl: String, userAgent: String): String {
                    return mockedOpenidConfig
                }

                override fun skipAllValidators(): Boolean = true
            }
        }

        assertThat(config.openidConfig).isEqualTo(TestUtils.discoveryDocument)
    }

    @Test
    fun createAndUpdateConfig_cache() {
        CryptoIntegration.init(javaClass.classLoader)
        objectUnderTest.postInit(null)

        var count = 0
        var userAgentResult = ""

        val serviceFactory: (KeycloakSession) -> GematikIDPService = {
            object : GematikIDPService(it) {
                override fun doGet(idpUrl: String, userAgent: String): String {
                    count++
                    userAgentResult = userAgent
                    return mockedOpenidConfig
                }

                override fun skipAllValidators(): Boolean = true
            }
        }

        objectUnderTest.createAndUpdateConfig(session, config, clock, serviceFactory)
        assertThat(count).isEqualTo(1)
        assertThat(userAgentResult).isEqualTo(userAgent)
        objectUnderTest.createAndUpdateConfig(session, config, clock, serviceFactory)
        assertThat(count).isEqualTo(1)

        assertThat(config.openidConfig).isEqualTo(TestUtils.discoveryDocument)

        //we are in the future +24h and document is expired
        val clock = Clock.fixed(Instant.ofEpochMilli(1667983621000), ZoneId.of("UTC"))
        objectUnderTest.createAndUpdateConfig(session, config, clock, serviceFactory)
        assertThat(count).isEqualTo(2)
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
