package de.bdr.servko.keycloak.gematik.idp

import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.keycloak.models.IdentityProviderModel

internal class GematikIDPConfigTest {

    @Test
    fun setTimeoutMs() {
        val timeout = "100000"
        val idpConfig = GematikIDPConfig()
        idpConfig.setTimeoutMs(timeout)

        Assertions.assertThat(idpConfig.config["timeoutMs"]).isEqualTo(timeout)
    }

    @Test
    fun getTimeoutMs() {
        val config= LinkedHashMap<String, String>()
        val timeout = 100000
        config["timeoutMs"] = timeout.toString()
        val model = IdentityProviderModel()
        model.config = config

        val idpConfig = GematikIDPConfig(model)

        Assertions.assertThat(idpConfig.getTimeoutMs()).isEqualTo(timeout)
    }

    @Test
    fun setIdpTimeoutMs() {
        val idpTimeout = "100000"
        val idpConfig = GematikIDPConfig()
        idpConfig.setIdpTimeoutMs(idpTimeout)

        Assertions.assertThat(idpConfig.config["idpTimeoutMs"]).isEqualTo(idpTimeout)
    }

    @Test
    fun getIdpTimeoutMs() {
        val config= LinkedHashMap<String, String>()
        val idpTimeout = 100000
        config["idpTimeoutMs"] = idpTimeout.toString()
        val model = IdentityProviderModel()
        model.config = config

        val idpConfig = GematikIDPConfig(model)

        Assertions.assertThat(idpConfig.getIdpTimeoutMs()).isEqualTo(idpTimeout)
    }
}
