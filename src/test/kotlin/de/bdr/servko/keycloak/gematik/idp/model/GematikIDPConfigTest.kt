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

package de.bdr.servko.keycloak.gematik.idp.model

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.junit.jupiter.params.provider.NullAndEmptySource
import org.junit.jupiter.params.provider.ValueSource
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig

internal class GematikIDPConfigTest {
    @Test
    fun getAuthenticatorAuthorizationUrl_NonEmptyAuthenticatorAuthorizationUrl_ReturnAuthenticatorAuthorizationUrl() {
        // arrange
        val authenticatorAuthorizationUrl = "authenticatorAuthorizationUrl"
        val idpConfig = initGematikIDPConfigWith("authenticatorAuthorizationUrl", authenticatorAuthorizationUrl)

        // act
        val result = idpConfig.getAuthenticatorAuthorizationUrl()

        // assert
        assertThat(result).isEqualTo(authenticatorAuthorizationUrl)
    }

    @Test
    fun getAuthenticatorAuthorizationUrl_NoAuthenticatorAuthorizationUrl_ReturnAuthorizationUrl() {
        // arrange
        val config = LinkedHashMap<String, String?>()
        val model = OIDCIdentityProviderConfig()
        model.config = config
        val authorizationUrl = "https://localhost:8081/sign_response"
        model.authorizationUrl = authorizationUrl

        val idpConfig = GematikIDPConfig(model)

        // act
        val result = idpConfig.getAuthenticatorAuthorizationUrl()

        // assert
        assertThat(result).isEqualTo(authorizationUrl)
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(
        strings = ["  ", // 2 whitespace
            "\t", // single tab
            "\n", // newline
            "\r"  // carriage return
        ]
    )
    fun getAuthenticatorAuthorizationUrl_EmptyAuthenticatorAuthorizationUrl_ReturnAuthorizationUrl(
        authenticatorAuthorizationUrl: String?,
    ) {
        // arrange
        val config = LinkedHashMap<String, String?>()
        config["authenticatorAuthorizationUrl"] = authenticatorAuthorizationUrl
        val model = OIDCIdentityProviderConfig()
        model.config = config
        val authorizationUrl = "https://localhost:8081/sign_response"
        model.authorizationUrl = authorizationUrl

        val idpConfig = GematikIDPConfig(model)

        // act
        val result = idpConfig.getAuthenticatorAuthorizationUrl()

        // assert
        assertThat(result).isEqualTo(authorizationUrl)
    }

    @Test
    fun setAuthenticatorAuthorizationUrl() {
        // arrange
        val authenticatorAuthorizationUrl = "authenticatorAuthorizationUrl"
        val idpConfig =
            initGematikIDPConfigWith("authenticatorAuthorizationUrl", authenticatorAuthorizationUrl + "_old")

        idpConfig.setAuthenticatorAuthorizationUrl(authenticatorAuthorizationUrl)

        // act
        val result = idpConfig.config["authenticatorAuthorizationUrl"]

        // assert
        assertThat(result).isEqualTo(authenticatorAuthorizationUrl)
    }


    @Test
    fun setTimeoutMs() {
        // arrange
        val timeout = "100000"
        val idpConfig = GematikIDPConfig()
        idpConfig.setTimeoutMs(timeout)

        // act
        val result = idpConfig.config["timeoutMs"]

        // assert
        assertThat(result).isEqualTo(timeout)
    }

    @Test
    fun getTimeoutMs() {
        // arrange
        val timeout = 100000
        val idpConfig = initGematikIDPConfigWith("timeoutMs", timeout.toString())

        // act
        val result = idpConfig.getTimeoutMs()

        // assert
        assertThat(result).isEqualTo(timeout)
    }

    @Test
    fun setIdpTimeoutMs() {
        // arrange
        val idpTimeout = "100000"
        val idpConfig = initGematikIDPConfig()
        idpConfig.setIdpTimeoutMs(idpTimeout)

        // act
        val result = idpConfig.config["idpTimeoutMs"]

        // assert
        assertThat(result).isEqualTo(idpTimeout)
    }

    @Test
    fun getIdpTimeoutMs() {
        // arrange
        val idpTimeout = 100000
        val idpConfig = initGematikIDPConfigWith("idpTimeoutMs", idpTimeout.toString())

        // act
        val result = idpConfig.getIdpTimeoutMs()

        // assert
        assertThat(result).isEqualTo(idpTimeout)
    }

    @Test
    fun getMultipleIdentityMode_true() {
        // arrange
        val multipleIdentityMode = true
        val idpConfig = initGematikIDPConfigWith("multipleIdentityMode", multipleIdentityMode.toString())

        // act
        val result = idpConfig.getMultipleIdentityMode()

        // assert
        assertThat(result).isEqualTo(multipleIdentityMode)
    }

    @Test
    fun getMultipleIdentityMode_false() {
        // arrange
        val multipleIdentityMode = false
        val idpConfig =
            initGematikIDPConfigWith("multipleIdentityModeauthenticationFlow", multipleIdentityMode.toString())

        // act
        val result = idpConfig.getMultipleIdentityMode()

        // assert
        assertThat(result).isEqualTo(multipleIdentityMode)
    }

    @Test
    fun getMultipleIdentityMode_null() {
        // arrange
        val multipleIdentityMode = null
        val idpConfig = initGematikIDPConfigWith("multipleIdentityMode", multipleIdentityMode.toString())

        // act
        val result = idpConfig.getMultipleIdentityMode()

        // assert
        assertThat(result).isEqualTo(false)
    }

    @ParameterizedTest
    @ValueSource(booleans = [true, false])
    fun setMultipleIdentityMode(multipleIdentityMode: Boolean) {
        // arrange
        val idpConfig = initGematikIDPConfig()
        idpConfig.setMultipleIdentityMode(multipleIdentityMode)

        // act
        val result = idpConfig.getMultipleIdentityMode()

        // assert
        assertThat(result).isEqualTo(multipleIdentityMode)
    }

    @ParameterizedTest
    @EnumSource(value = AuthenticationFlowType::class)
    fun getAuthenticationFlow_enumValue(type: AuthenticationFlowType) {
        // arrange
        val idpConfig = initGematikIDPConfigWith("authenticationFlow", type.toString())

        // act
        val result = idpConfig.getAuthenticationFlow()

        // assert
        assertThat(result).isEqualTo(type)
    }

    @Test
    fun getAuthenticationFlow_null() {
        // arrange
        val config = LinkedHashMap<String, String>()
        val authenticationFlow = null
        config["authenticationFlow"] = authenticationFlow.toString()
        val model = OIDCIdentityProviderConfig()
        model.config = config

        val idpConfig = GematikIDPConfig(model)

        // act
        val result = idpConfig.getAuthenticationFlow()

        // assert
        assertThat(result).isEqualTo(AuthenticationFlowType.LEGACY)
    }

    @ParameterizedTest
    @EnumSource(value = AuthenticationFlowType::class)
    fun setAuthenticationFlow(type: AuthenticationFlowType) {
        // arrange
        val idpConfig = initGematikIDPConfig()
        idpConfig.setAuthenticationFlow(type)

        // act
        val result = idpConfig.getAuthenticationFlow()

        // assert
        assertThat(result).isEqualTo(type)
    }

    @Test
    fun `isCaseSensitiveOriginalUsername - Is Called - Always Returns True`() {
        // arrange
        val idpConfig = initGematikIDPConfig()

        // act
        val result = idpConfig.isCaseSensitiveOriginalUsername

        // assert
        assertThat(result).isTrue()
    }

    private fun initGematikIDPConfig(): GematikIDPConfig {
        val config = LinkedHashMap<String, String>()
        val model = OIDCIdentityProviderConfig()
        model.config = config
        return GematikIDPConfig(model)
    }

    private fun initGematikIDPConfigWith(configKey: String, configValue: String): GematikIDPConfig {
        val config = LinkedHashMap<String, String>()
        config[configKey] = configValue
        val model = OIDCIdentityProviderConfig()
        model.config = config

        val idpConfig = GematikIDPConfig(model)
        return idpConfig
    }
}
