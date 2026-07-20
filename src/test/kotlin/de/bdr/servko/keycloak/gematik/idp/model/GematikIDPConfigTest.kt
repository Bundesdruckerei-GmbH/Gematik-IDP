/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.model

import de.bdr.servko.keycloak.gematik.idp.exception.InvalidAuthenticationFlowException
import de.bdr.servko.keycloak.gematik.idp.exception.InvalidAuthenticatorVersionException
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.junit.jupiter.params.provider.NullAndEmptySource
import org.junit.jupiter.params.provider.ValueSource
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.models.RealmModel
import org.mockito.Mockito

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
    fun getAuthenticatorVersion_NonEmptyAuthenticatorVersion_ReturnAuthenticatorVersion() {
        // arrange
        val authenticatorVersion = "4.6.0"
        val idpConfig = initGematikIDPConfigWith("authenticatorVersion", authenticatorVersion)

        // act
        val result = idpConfig.getAuthenticatorVersion()

        // assert
        assertThat(result).isEqualTo(authenticatorVersion)
    }

    @Test
    fun getAuthenticatorVersion_blankAuthenticatorVersion() {
        // arrange
        val idpConfig = initGematikIDPConfigWith("authenticatorVersion", "")

        // act
        val result = idpConfig.getAuthenticatorVersion()

        // assert
        assertThat(result).isEqualTo("4.6.0")
    }

    @Test
    fun getAuthenticatorVersion_AuthenticatorVersionNotGiven() {
        // arrange
        val idpConfig = GematikIDPConfig()

        // act
        val result = idpConfig.getAuthenticatorVersion()

        // assert
        assertThat(result).isEqualTo("4.6.0")
    }

    @Test
    fun setAuthenticatorVersion() {
        // arrange
        val authenticatorVersion = "4.6.0"
        val idpConfig = GematikIDPConfig()
        idpConfig.setAuthenticatorVersion(authenticatorVersion)

        // act
        val result = idpConfig.config["authenticatorVersion"]

        // assert
        assertThat(result).isEqualTo(authenticatorVersion)
    }

    @Test
    fun setLoginTimeoutMs() {
        // arrange
        val loginTimeoutMs = "20000"
        val idpConfig = GematikIDPConfig()
        idpConfig.setLoginTimeoutMs(loginTimeoutMs)

        // act
        val result = idpConfig.config["loginTimeoutMs"]

        // assert
        assertThat(result).isEqualTo(loginTimeoutMs)
    }

    @Test
    fun getLoginTimeoutMs() {
        // arrange
        val loginTimeout = 20000
        val idpConfig = initGematikIDPConfigWith("loginTimeoutMs", loginTimeout.toString())

        // act
        val result = idpConfig.getLoginTimeoutMs()

        // assert
        assertThat(result).isEqualTo(loginTimeout)
    }

    @Test
    fun getLoginTimeoutMs_LoginTimeoutMsNotGiven() {
        // arrange
        val idpConfig = GematikIDPConfig()

        // act
        val result = idpConfig.getLoginTimeoutMs()

        // assert
        assertThat(result).isEqualTo(600000)
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
    fun getAuthenticatorHttpServerTimeoutMs() {
        // arrange
        val httpServerTimeout = 16000
        val idpConfig = initGematikIDPConfigWith("authenticatorHttpServerTimeoutMs", httpServerTimeout.toString())

        // act
        val result = idpConfig.getAuthenticatorHttpServerTimeoutMs()

        // assert
        assertThat(result).isEqualTo(httpServerTimeout)
    }

    @Test
    fun setAuthenticatorHttpServerTimeoutMs() {
        // arrange
        val httpServerTimeout = "100000"
        val idpConfig = initGematikIDPConfig()
        idpConfig.setAuthenticatorHttpServerTimeoutMs(httpServerTimeout)

        // act
        val result = idpConfig.config["authenticatorHttpServerTimeoutMs"]

        // assert
        assertThat(result).isEqualTo(httpServerTimeout)
    }


    @Test
    fun getAuthenticatorHttpServerTimeoutMs_AuthenticatorHttpServerTimeoutMsNotGiven() {
        // arrange
        val idpConfig = GematikIDPConfig()

        // act
        val result = idpConfig.getAuthenticatorHttpServerTimeoutMs()

        // assert
        assertThat(result).isEqualTo(10000)
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
    @ValueSource(booleans = [true, false])
    fun setAuthenticatorAutoLaunch(authenticatorAutoLaunch: Boolean) {
        // arrange
        val idpConfig = initGematikIDPConfig()
        idpConfig.setAuthenticatorAutoLaunch(authenticatorAutoLaunch)

        // act
        val result = idpConfig.getAuthenticatorAutoLaunch()

        // assert
        assertThat(result).isEqualTo(authenticatorAutoLaunch)
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
        assertThat(result).isEqualTo(AuthenticationFlowType.MULTI)
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

    @Test
    fun `validate - invalid Authentication Flow type throws exception`() {
        // arrange
        val idpConfig = initGematikIDPConfigWith("authenticationFlow", "INVALID_FLOW_TYPE")

        // assert
        assertThrows<InvalidAuthenticationFlowException> {
            idpConfig.validate(null)
        }
    }

    @ParameterizedTest
    @EnumSource(value = AuthenticationFlowType::class)
    fun `validate - Authentication Flow type updated without Exception`(type: AuthenticationFlowType) {
        // arrange
        val idpConfig = initGematikIDPConfigWith("authenticationFlow", type.toString())
        val realm = Mockito.mock(RealmModel::class.java)

        // assert
        assertDoesNotThrow {
            idpConfig.validate(realm)
        }
    }

    @Test
    fun `validate - outdated Authentication Version throws exception`() {
        // arrange
        val idpConfig = initGematikIDPConfigWith("authenticationFlow", AuthenticationFlowType.SMCB.toString())
        idpConfig.setAuthenticatorVersion("3.0.0")
        val realm = Mockito.mock(RealmModel::class.java)

        // assert
        assertThrows<InvalidAuthenticatorVersionException> {
            idpConfig.validate(realm)
        }
    }

    @Test
    fun `validate - valid major Authentication Version updated without exception`() {
        // arrange
        val idpConfig = initGematikIDPConfigWith("authenticationFlow", AuthenticationFlowType.HBA.toString())
        idpConfig.setAuthenticatorVersion("5.0.0")
        val realm = Mockito.mock(RealmModel::class.java)

        // assert
        assertDoesNotThrow {
            idpConfig.validate(realm)
        }
    }

    @Test
    fun `validate - invalid Authentication Version throws exception`() {
        // arrange
        val idpConfig = initGematikIDPConfigWith("authenticationFlow", AuthenticationFlowType.HBA.toString())
        idpConfig.setAuthenticatorVersion("3.X")
        val realm = Mockito.mock(RealmModel::class.java)

        // assert
        assertThrows<InvalidAuthenticatorVersionException> {
            idpConfig.validate(realm)
        }
    }

    @Test
    fun `validate - valid Authentication Version updated without exception`() {
        // arrange
        val idpConfig = initGematikIDPConfigWith("authenticationFlow", AuthenticationFlowType.MULTI.toString())
        idpConfig.setAuthenticatorVersion("4.7.0")

        val realm = Mockito.mock(RealmModel::class.java)

        // assert
        assertDoesNotThrow {
            idpConfig.validate(realm)
        }
    }

    @Test
    fun `validate - default Authentication Version updated without exception`() {
        // arrange
        val idpConfig = initGematikIDPConfigWith("authenticationFlow", AuthenticationFlowType.HBA.toString())
        idpConfig.setAuthenticatorVersion("4.6.0")

        val realm = Mockito.mock(RealmModel::class.java)

        // assert
        assertDoesNotThrow {
            idpConfig.validate(realm)
        }
    }

    @Test
    fun `validate - empty Authentication Version is ignored`() {
        // arrange
        val realm = Mockito.mock(RealmModel::class.java)
        val idpConfig = initGematikIDPConfigWith("authenticationFlow", AuthenticationFlowType.SMCB.toString())
        idpConfig.setAuthenticatorVersion("")

        // assert
        assertDoesNotThrow {
            idpConfig.validate(realm)
        }
    }

    @Test
    fun `validate - unset Authentication Version is ignored`() {
        // arrange
        val realm = Mockito.mock(RealmModel::class.java)
        val idpConfig = initGematikIDPConfigWith("authenticationFlow", AuthenticationFlowType.SMCB.toString())

        // assert
        assertDoesNotThrow {
            idpConfig.validate(realm)
        }
    }

    @Test
    fun `validate - authenticator start port range less than MIN PORT`() {
        // arrange
        val realm = Mockito.mock(RealmModel::class.java)
        val idpConfig = initGematikIDPConfigWith("authenticatorPortRangeStart", "1000")

        // assert
        assertThrows<IllegalArgumentException> {
            idpConfig.validate(realm)
        }
    }

    @Test
    fun `validate - authenticator start port range higher than MAX PORT`() {
        // arrange
        val realm = Mockito.mock(RealmModel::class.java)
        val idpConfig = initGematikIDPConfigWith("authenticatorPortRangeStart", "70000")

        // assert
        assertThrows<IllegalArgumentException> {
            idpConfig.validate(realm)
        }
    }

    @Test
    fun `validate - authenticator end port range less than MIN PORT`() {
        // arrange
        val realm = Mockito.mock(RealmModel::class.java)
        val idpConfig = initGematikIDPConfigWith("authenticatorPortRangeEnd", "1000")

        // assert
        assertThrows<IllegalArgumentException> {
            idpConfig.validate(realm)
        }
    }

    @Test
    fun `validate - authenticator end port range higher than MAX PORT`() {
        // arrange
        val realm = Mockito.mock(RealmModel::class.java)
        val idpConfig = initGematikIDPConfigWith("authenticatorPortRangeEnd", "70000")

        // assert
        assertThrows<IllegalArgumentException> {
            idpConfig.validate(realm)
        }
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

    // ---------------------------------------------------------------------
    // Port range related tests
    // ---------------------------------------------------------------------

    @Test
    fun `setAuthenticatorPortRangeStart stores value in config map`() {
        // arrange
        val start = 1000
        val idpConfig = initGematikIDPConfig()

        // act
        idpConfig.setAuthenticatorPortRangeStart(start)

        // assert
        assertThat(idpConfig.config["authenticatorPortRangeStart"]).isEqualTo(start.toString())
    }

    @Test
    fun `getAuthenticatorPortRangeStart returns stored value`() {
        // arrange
        val start = 2000
        val idpConfig = initGematikIDPConfigWith("authenticatorPortRangeStart", start.toString())

        // act
        val result = idpConfig.getAuthenticatorPortRangeStart()

        // assert
        assertThat(result).isEqualTo(start)
    }

    @Test
    fun `getAuthenticatorPortRangeStart returns default when not set`() {
        // arrange
        val idpConfig = initGematikIDPConfig()

        // act
        val result = idpConfig.getAuthenticatorPortRangeStart()

        // assert
        assertThat(result).isEqualTo(1024)
    }

    @Test
    fun `setAuthenticatorPortRangeEnd stores value in config map`() {
        // arrange
        val end = 5000
        val idpConfig = initGematikIDPConfig()

        // act
        idpConfig.setAuthenticatorPortRangeEnd(end)

        // assert
        assertThat(idpConfig.config["authenticatorPortRangeEnd"]).isEqualTo(end.toString())
    }

    @Test
    fun `getAuthenticatorPortRangeEnd returns stored value`() {
        // arrange
        val end = 6000
        val idpConfig = initGematikIDPConfigWith("authenticatorPortRangeEnd", end.toString())

        // act
        val result = idpConfig.getAuthenticatorPortRangeEnd()

        // assert
        assertThat(result).isEqualTo(end)
    }

    @Test
    fun `getAuthenticatorPortRangeEnd returns default when not set`() {
        // arrange
        val idpConfig = initGematikIDPConfig()

        // act
        val result = idpConfig.getAuthenticatorPortRangeEnd()

        // assert
        assertThat(result).isEqualTo(65535)
    }

}
