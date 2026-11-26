package de.bdr.servko.keycloak.gematik.idp.util

import de.bdr.servko.keycloak.gematik.idp.model.AuthenticatorErrorTypes
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPStep
import jakarta.ws.rs.core.Response
import org.junit.jupiter.api.Test
import org.keycloak.sessions.AuthenticationSessionModel
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mockito.*
import org.assertj.core.api.Assertions.assertThat

class ErrorUtilsTest {

    @Test
    fun `saveUnsupportedAuthenticatorVersion should set correct error notes in session`() {
        // arrange
        val authSession = mock(AuthenticationSessionModel::class.java)
        val minVersion = "4.6.0"
        val expectedErrorDetails = minVersion

        // act
        val response = ErrorUtils.saveUnsupportedAuthenticatorVersion(authSession, minVersion)

        // assert
        assertThat(response.status).isEqualTo(Response.Status.NO_CONTENT.statusCode)
        
        verify(authSession).setAuthNote(eq(GematikIdpLiterals.ERROR), eq(AuthenticatorErrorTypes.UNSUPPORTED_AUTHENTICATOR_VERSION.error))
        verify(authSession).setAuthNote(eq(GematikIdpLiterals.ERROR_DETAILS), eq(expectedErrorDetails))
        verify(authSession).setAuthNote(eq(GematikIdpLiterals.GEMATIK_IDP_STEP), eq(GematikIDPStep.ERROR.name))
        verify(authSession).setAuthNote(eq(GematikIdpLiterals.ERROR_URI), eq(null))
    }
}
