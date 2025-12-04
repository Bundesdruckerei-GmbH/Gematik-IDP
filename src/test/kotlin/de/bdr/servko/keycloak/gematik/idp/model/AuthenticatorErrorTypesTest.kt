/*
 *  Copyright 2025 Bundesdruckerei GmbH and/or its affiliates
 *  and other contributors.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package de.bdr.servko.keycloak.gematik.idp.model

import org.assertj.core.api.Assertions
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.junit.jupiter.params.provider.NullAndEmptySource
import org.junit.jupiter.params.provider.ValueSource
import java.util.stream.Stream


class AuthenticatorErrorTypesTest {
    companion object {
        @JvmStatic
        private fun provideErrorMappings(): Stream<Arguments> {
            return Stream.of(
                Arguments.of(AuthenticatorErrorTypes.LOGIN_TIMEOUT, "loginTimeout"),
                Arguments.of(AuthenticatorErrorTypes.NON_FINAL_STEP, "authenticator.nonFinalStep"),
                Arguments.of(AuthenticatorErrorTypes.INCOMPLETE_IDP_DATA, "authenticator.incompleteIdpData"),
                Arguments.of(AuthenticatorErrorTypes.UNSUPPORTED_CARD_TYPE, "authenticator.unsupportedCardType"),
                Arguments.of(
                    AuthenticatorErrorTypes.UNSUPPORTED_AUTHENTICATOR_VERSION,
                    "authenticator.unsupportedAuthenticatorVersion"
                ),
                Arguments.of(AuthenticatorErrorTypes.CONSENT_DECLINED, "authenticator.consentDeclined"),
            )
        }
    }

    @ParameterizedTest
    @MethodSource("provideErrorMappings")
    fun `valueOf - Input is known error message key - Maps to matching error type`(errorTypes: AuthenticatorErrorTypes, error: String?) {
        // arrange + act + assert
        Assertions.assertThat(AuthenticatorErrorTypes.valueOf(error)).isEqualTo(errorTypes)
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = [
        "nonFinalStep",
        "authenticatorIncompleteIdpData",
        "auth.unsupportedCardType",
        "authenticator.unknownAuthenticatorVersion",
    ])
    fun `valueOf - Input is unknown error message key - Maps to generic idp error type`(error: String?) {
        // arrange + act + assert
        Assertions.assertThat(AuthenticatorErrorTypes.valueOf(error)).isEqualTo(AuthenticatorErrorTypes.ERROR_IDP)
    }
}
