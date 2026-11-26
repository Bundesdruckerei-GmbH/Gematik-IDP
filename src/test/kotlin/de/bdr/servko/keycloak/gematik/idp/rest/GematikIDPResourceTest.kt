/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.GematikIDP
import de.bdr.servko.keycloak.gematik.idp.exception.ClientException
import de.bdr.servko.keycloak.gematik.idp.exception.SessionNotFoundException
import de.bdr.servko.keycloak.gematik.idp.model.AuthenticationCardType
import de.bdr.servko.keycloak.gematik.idp.model.AuthenticationFlowType
import de.bdr.servko.keycloak.gematik.idp.model.AuthenticatorErrorTypes
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import de.bdr.servko.keycloak.gematik.idp.service.GematikIDPService
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals
import de.bdr.servko.keycloak.gematik.idp.validation.GematikIdpCertificateValidatorProvider
import jakarta.ws.rs.core.Response
import org.assertj.core.api.Assertions.assertThat
import org.jboss.logging.Logger
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.sessions.AuthenticationSessionModel
import org.mockito.kotlin.*
import java.net.URI

internal class GematikIDPResourceTest {

    private val realmMock = mock<RealmModel>()
    private val callbackMock = mock<UserAuthenticationIdentityProvider.AuthenticationCallback>()
    private val certificateValidator = mock<GematikIdpCertificateValidatorProvider>()
    private val sessionMock = mock<KeycloakSession>() {
        on { getProvider(GematikIdpCertificateValidatorProvider::class.java) } doReturn certificateValidator
    }
    private val idp = mock<GematikIDP>()
    private val formsMock = mock<LoginFormsProvider>()
    private val config = mock<GematikIDPConfig>()
    private val serviceMock = mock<GematikIDPService>()
    private val loggerMock = mock<Logger>()

    private fun createTestResource() = TestGematikIDPResource(
        realm = realmMock,
        callback = callbackMock,
        session = sessionMock,
        gematikIDP = idp,
        config = config,
        service = serviceMock,
        forms = formsMock,
        logger = loggerMock
    )

    @ParameterizedTest(name = "Flow {0} should return {1}")
    @CsvSource(
        "MULTI, GematikIDPMultiResource",
        "HBA, GematikIDPHbaResource",
        "SMCB, GematikIDPSmcbResource"
    )
    fun `fromConfig returns correct resource based on flow type`(
        flowTypeStr: String,
        expectedResourceSimpleName: String,
    ) {
        // arrange
        val flowType = AuthenticationFlowType.valueOf(flowTypeStr)
        whenever(config.getAuthenticationFlow()).thenReturn(flowType)

        // act
        val result = GematikIDPResource.from(
            realm = realmMock,
            callback = callbackMock,
            session = sessionMock,
            gematikIDP = idp,
            config = config,
            forms = formsMock,
        )

        // assert
        assertThat(result::class.simpleName).isEqualTo(expectedResourceSimpleName)
    }

    @Test
    fun `withAuthSession - success - calls block`() {
        // arrange
        val encodedState = "valid-state"
        val authSessionMock = mock<AuthenticationSessionModel>()
        val expectedResponse = Response.ok().build()

        whenever(serviceMock.resolveAuthSessionFromEncodedState(realmMock, encodedState)).thenReturn(authSessionMock)
        whenever(config.getLoginTimeoutMs()).thenReturn(0) // disable timeout

        val resource = createTestResource()

        // act
        val result = resource.testWithAuthSession(encodedState) {
            expectedResponse
        }

        // assert
        assertThat(result).isEqualTo(expectedResponse)
        verify(serviceMock).resolveAuthSessionFromEncodedState(realmMock, encodedState)
    }

    @Test
    fun `withAuthSession - session not found - without callback - calls handleSessionTimeout`() {
        // arrange
        val encodedState = "invalid-state"
        val exception = SessionNotFoundException("Not found")
        val errorResponse = Response.status(Response.Status.BAD_REQUEST).build()

        whenever(serviceMock.resolveAuthSessionFromEncodedState(realmMock, encodedState)).thenThrow(exception)
        whenever(formsMock.setError(any(), any())).thenReturn(formsMock)
        whenever(formsMock.createErrorPage(any())).thenReturn(errorResponse)

        val resource = createTestResource()

        // act
        val result = resource.testWithAuthSession(encodedState) {
            Response.ok().build()
        }

        // assert
        assertThat(result).isEqualTo(errorResponse)
        verify(formsMock).setError(AuthenticatorErrorTypes.LOGIN_TIMEOUT.error, exception.message)
        verify(formsMock).createErrorPage(Response.Status.BAD_REQUEST)
    }

    @Test
    fun `withAuthSession - session not found - with callback - calls callback`() {
        // arrange
        val encodedState = "invalid-state"
        val exception = SessionNotFoundException("Not found")
        val callbackResponse = Response.status(Response.Status.SERVICE_UNAVAILABLE).build()

        whenever(serviceMock.resolveAuthSessionFromEncodedState(realmMock, encodedState)).thenThrow(exception)

        val resource = createTestResource()

        // act
        val result = resource.testWithAuthSession(
            encodedState = encodedState,
            onSessionNotFound = { callbackResponse }
        ) {
            Response.ok().build()
        }

        // assert
        assertThat(result).isEqualTo(callbackResponse)
    }

    @Test
    fun `withAuthSession - client exception - calls handleInternalError`() {
        // arrange
        val encodedState = "invalid-client-state"
        val exception = ClientException("Client disabled")
        val errorResponse = Response.status(Response.Status.BAD_REQUEST).build()

        whenever(serviceMock.resolveAuthSessionFromEncodedState(realmMock, encodedState)).thenThrow(exception)
        whenever(formsMock.setError(any(), any())).thenReturn(formsMock)
        whenever(formsMock.createErrorPage(any())).thenReturn(errorResponse)

        val resource = createTestResource()

        // act
        val result = resource.testWithAuthSession(encodedState) {
            Response.ok().build()
        }

        // assert
        assertThat(result).isEqualTo(errorResponse)
        verify(loggerMock).error("Client not found or disabled during auth session resolution", exception)
        verify(formsMock).setError(AuthenticatorErrorTypes.ERROR_IDP.error, exception.message)
        verify(formsMock).createErrorPage(Response.Status.BAD_REQUEST)
    }

    @Test
    fun `withAuthSession - generic exception - returns internal server error`() {
        // arrange
        val encodedState = "error-state"
        whenever(
            serviceMock.resolveAuthSessionFromEncodedState(
                realmMock,
                encodedState
            )
        ).thenThrow(RuntimeException("Oops"))

        val resource = createTestResource()

        // act
        val result = resource.testWithAuthSession(encodedState) {
            Response.ok().build()
        }

        // assert
        assertThat(result.status).isEqualTo(Response.Status.INTERNAL_SERVER_ERROR.statusCode)
        verify(loggerMock).error(eq("Failed to resolve auth session"), any<RuntimeException>())
    }

    @Test
    fun `withAuthSession - login timed out - calls handleLoginTimeout`() {
        // arrange
        val encodedState = "timed-out-state"
        val authSessionMock = mock<AuthenticationSessionModel>()
        val errorResponse = Response.status(Response.Status.BAD_REQUEST).build()

        whenever(serviceMock.resolveAuthSessionFromEncodedState(realmMock, encodedState)).thenReturn(authSessionMock)
        whenever(config.getLoginTimeoutMs()).thenReturn(1000)
        whenever(authSessionMock.getAuthNote(GematikIdpLiterals.LOGIN_START_TIME_NOTE)).thenReturn("1000") // Very old timestamp
        whenever(formsMock.setError(any(), any())).thenReturn(formsMock)
        whenever(formsMock.createErrorPage(any())).thenReturn(errorResponse)

        val resource = createTestResource()

        // act
        val result = resource.testWithAuthSessionAndLoginTimeout(encodedState) {
            Response.ok().build()
        }

        // assert
        assertThat(result.status).withFailMessage("Expected HTTP status 400 (Bad Request) but got %s", result.status).isEqualTo(Response.Status.BAD_REQUEST.statusCode)
        verify(formsMock).setError(AuthenticatorErrorTypes.LOGIN_TIMEOUT.error, "Login timeout. Please log in again.")
        verify(formsMock).createErrorPage(Response.Status.BAD_REQUEST)
    }

    internal class TestGematikIDPResource(
        override val realm: RealmModel,
        override val callback: UserAuthenticationIdentityProvider.AuthenticationCallback,
        override val session: KeycloakSession,
        override val gematikIDP: GematikIDP,
        override val config: GematikIDPConfig,
        override val service: GematikIDPService,
        override val forms: LoginFormsProvider,
        override val logger: Logger,
    ) : GematikIDPResource() {
        override val initialStepName: String = "testStep"
        override val initialFlowCardType: AuthenticationFlowType = AuthenticationFlowType.HBA
        override val startingCardType: AuthenticationCardType = AuthenticationCardType.HBA

        override fun status(encodedState: String): Response = Response.ok().build()
        override fun nextStep(encodedState: String): Response = Response.ok().build()
        override fun result(
            code: String?,
            encodedState: String?,
            cardType: String?,
            error: String?,
            errorDetails: String?,
            errorDescription: String?,
            errorUri: String?,
            userAgent: String?,
        ): Response = Response.ok().build()

        override fun probeAuthenticatorServerUrl(authenticatorPort: Int): URI = 
            URI("http://localhost:$authenticatorPort/status")

        fun testWithAuthSession(
            encodedState: String,
            onSessionNotFound: ((SessionNotFoundException) -> Response)? = null,
            block: (AuthenticationSessionModel) -> Response,
        ) = withAuthSession(encodedState, onSessionNotFound, block)

        fun testWithAuthSessionAndLoginTimeout(
            encodedState: String,
            onSessionNotFound: ((SessionNotFoundException) -> Response)? = null,
            block: (AuthenticationSessionModel) -> Response,
        ) = withAuthSessionAndLoginTimeout(encodedState, onSessionNotFound, block)
    }
}
