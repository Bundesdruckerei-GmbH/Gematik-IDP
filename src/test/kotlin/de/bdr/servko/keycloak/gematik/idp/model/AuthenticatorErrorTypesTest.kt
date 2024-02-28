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
                Arguments.of(AuthenticatorErrorTypes.NON_FINAL_STEP, "authenticator.nonFinalStep"),
                Arguments.of(AuthenticatorErrorTypes.INCOMPLETE_IDP_DATA, "authenticator.incompleteIdpData"),
                Arguments.of(AuthenticatorErrorTypes.UNSUPPORTED_CARD_TYPE, "authenticator.unsupportedCardType"),
                Arguments.of(
                    AuthenticatorErrorTypes.UNSUPPORTED_AUTHENTICATOR_VERSION,
                    "authenticator.unsupportedAuthenticatorVersion"
                )
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
        "authenticator.unknownAuthenticatorVersion"
    ])
    fun `valueOf - Input is unknown error message key - Maps to generic idp error type`(error: String?) {
        // arrange + act + assert
        Assertions.assertThat(AuthenticatorErrorTypes.valueOf(error)).isEqualTo(AuthenticatorErrorTypes.ERROR_IDP)
    }
}
