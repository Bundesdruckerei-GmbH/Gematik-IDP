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
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.NullAndEmptySource
import org.junit.jupiter.params.provider.ValueSource
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig

internal class GematikIDPConfigTest {
    @Test
    fun getAuthenticatorAuthorizationUrl_NonEmptyAuthenticatorAuthorizationUrl_ReturnAuthenticatorAuthorizationUrl() {
        val config= LinkedHashMap<String, String>()
        val authenticatorAuthorizationUrl = "authenticatorAuthorizationUrl"
        config["authenticatorAuthorizationUrl"] = authenticatorAuthorizationUrl
        val model = OIDCIdentityProviderConfig()
        model.config = config

        val idpConfig = GematikIDPConfig(model)

        Assertions.assertThat(idpConfig.getAuthenticatorAuthorizationUrl()).isEqualTo(authenticatorAuthorizationUrl)
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = [
        "  ", // 2 whitespace
        "\t", // single tab
        "\n", // newline
        "\r"  // carriage return
    ])
    fun getAuthenticatorAuthorizationUrl_EmptyAuthenticatorAuthorizationUrl_ReturnAuthorizationUrl(authenticatorAuthorizationUrl: String?) {
        val config= LinkedHashMap<String, String?>()
        config["authenticatorAuthorizationUrl"] = authenticatorAuthorizationUrl
        val model = OIDCIdentityProviderConfig()
        model.config = config
        val authorizationUrl = "https://localhost:8081/sign_response"
        model.authorizationUrl = authorizationUrl

        val idpConfig = GematikIDPConfig(model)

        Assertions.assertThat(idpConfig.getAuthenticatorAuthorizationUrl()).isEqualTo(authorizationUrl)
    }

    @Test
    fun setAuthenticatorAuthorizationUrl() {
        val config= LinkedHashMap<String, String>()
        val authenticatorAuthorizationUrl = "authenticatorAuthorizationUrl"
        config["authenticatorAuthorizationUrl"] = authenticatorAuthorizationUrl
        val model = OIDCIdentityProviderConfig()
        model.config = config

        val idpConfig = GematikIDPConfig(model)
        idpConfig.setAuthenticatorAuthorizationUrl(authenticatorAuthorizationUrl)

        Assertions.assertThat(model.config["authenticatorAuthorizationUrl"]).isEqualTo(authenticatorAuthorizationUrl)
    }


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
        val model = OIDCIdentityProviderConfig()
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
        val model = OIDCIdentityProviderConfig()
        model.config = config

        val idpConfig = GematikIDPConfig(model)

        Assertions.assertThat(idpConfig.getIdpTimeoutMs()).isEqualTo(idpTimeout)
    }

    @Test
    fun getMultipleIdentityMode_true() {
        val config= LinkedHashMap<String, String>()
        val multipleIdentityMode = true
        config["multipleIdentityMode"] = multipleIdentityMode.toString()
        val model = OIDCIdentityProviderConfig()
        model.config = config

        val idpConfig = GematikIDPConfig(model)

        Assertions.assertThat(idpConfig.getMultipleIdentityMode()).isEqualTo(multipleIdentityMode)
    }

    @Test
    fun getMultipleIdentityMode_false() {
        val config= LinkedHashMap<String, String>()
        val multipleIdentityMode = false
        config["multipleIdentityMode"] = multipleIdentityMode.toString()
        val model = OIDCIdentityProviderConfig()
        model.config = config

        val idpConfig = GematikIDPConfig(model)

        Assertions.assertThat(idpConfig.getMultipleIdentityMode()).isEqualTo(multipleIdentityMode)
    }

    @Test
    fun getMultipleIdentityMode_null() {
        val config= LinkedHashMap<String, String>()
        val multipleIdentityMode = null
        config["multipleIdentityMode"] = multipleIdentityMode.toString()
        val model = OIDCIdentityProviderConfig()
        model.config = config

        val idpConfig = GematikIDPConfig(model)

        Assertions.assertThat(idpConfig.getMultipleIdentityMode()).isEqualTo(false)
    }

    @ParameterizedTest
    @ValueSource(booleans = [true, false])
    fun setMultipleIdentityMode(multipleIdentityMode: Boolean) {
        val config= LinkedHashMap<String, String>()
        val model = OIDCIdentityProviderConfig()
        model.config = config

        val idpConfig = GematikIDPConfig(model)
        idpConfig.setMultipleIdentityMode(multipleIdentityMode)

        Assertions.assertThat(idpConfig.getMultipleIdentityMode()).isEqualTo(multipleIdentityMode)
    }

    @Test
    fun getNewAuthenticationFlow_true() {
        val config= LinkedHashMap<String, String>()
        val newAuthenticationFlow = true
        config["newAuthenticationFlow"] = newAuthenticationFlow.toString()
        val model = OIDCIdentityProviderConfig()
        model.config = config

        val idpConfig = GematikIDPConfig(model)

        Assertions.assertThat(idpConfig.getNewAuthenticationFlow()).isEqualTo(newAuthenticationFlow)
    }

    @Test
    fun getNewAuthenticationFlow_false() {
        val config= LinkedHashMap<String, String>()
        val newAuthenticationFlow = false
        config["newAuthenticationFlow"] = newAuthenticationFlow.toString()
        val model = OIDCIdentityProviderConfig()
        model.config = config

        val idpConfig = GematikIDPConfig(model)

        Assertions.assertThat(idpConfig.getNewAuthenticationFlow()).isEqualTo(newAuthenticationFlow)
    }

    @Test
    fun getNewAuthenticationFlow_null() {
        val config= LinkedHashMap<String, String>()
        val newAuthenticationFlow = null
        config["newAuthenticationFlow"] = newAuthenticationFlow.toString()
        val model = OIDCIdentityProviderConfig()
        model.config = config

        val idpConfig = GematikIDPConfig(model)

        Assertions.assertThat(idpConfig.getNewAuthenticationFlow()).isEqualTo(false)
    }

    @ParameterizedTest
    @ValueSource(booleans = [true, false])
    fun setNewAuthenticationFlow(multipleIdentityMode: Boolean) {
        val config= LinkedHashMap<String, String>()
        val model = OIDCIdentityProviderConfig()
        model.config = config

        val idpConfig = GematikIDPConfig(model)
        idpConfig.setNewAuthenticationFlow(multipleIdentityMode)

        Assertions.assertThat(idpConfig.getNewAuthenticationFlow()).isEqualTo(multipleIdentityMode)
    }
}
