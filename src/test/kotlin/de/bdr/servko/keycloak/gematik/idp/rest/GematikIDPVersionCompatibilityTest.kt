/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.GematikIDP
import de.bdr.servko.keycloak.gematik.idp.model.*
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpCertificateService
import jakarta.ws.rs.core.Response
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.mockito.kotlin.*
import org.jose4j.jwt.consumer.JwtContext

internal class GematikIDPVersionCompatibilityTest : GematikIDPEndpointBaseTest() {
    private val certificateService = mock<GematikIdpCertificateService>()

    private val idp = GematikIDP(sessionMock, config)

    private val underTest = GematikIDPHbaResource(
        realmMock, callbackMock, sessionMock, idp, config, service, formsMock, certificateService
    )

    @BeforeEach
    fun setUp() {
        whenever(sessionMock.authenticationSessions()).thenReturn(authenticationSession)
        whenever(authenticationSession.getRootAuthenticationSession(realmMock, ROOT_SESSION_ID)).thenReturn(
            rootAuthenticationSession
        )
    }

    @ParameterizedTest
    @CsvSource(
        "4.17.1, 4.16.1, HBA, true",  // Scenario A: Min 4.17.1, Req 4.16.1 -> Error
        "4.17.1, 4.17.0, HBA, true",  // Scenario B: Min 4.17.1, Req 4.17.0 -> Error
        "4.17.1, 4.17.2, HBA, false", // Scenario C: Min 4.17.1, Req 4.17.2 -> No Error
        "4.17.1, 4.16.1, , true",     // Scenario D: Min 4.17.1, Req 4.16.1, No CardType -> Error
        "4.17.1, 4.17.0, , true",     // Scenario D: Min 4.17.1, Req 4.17.0, No CardType -> Error
        "4.17.1, 4.17.2, , false",    // Scenario D: Min 4.17.1, Req 4.17.2, No CardType -> No Error
    )
    fun `result - version compatibility check`(
        minVersion: String,
        requestVersion: String,
        cardType: String?,
        expectError: Boolean
    ) {
        // arrange
        config.setAuthenticatorVersion(minVersion)
        
        // Mocking result to not fail on other things
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP")).thenReturn(GematikIDPStep.REQUESTED_HBA_DATA.name)
        
        // Use a specific verifier for the session
        val verifier = "some-verifier"
        whenever(authSessionMock.getAuthNote("CODE_VERIFIER")).thenReturn(verifier)
        
        // Mock callback.error to avoid NPE in the result's else branch (when cardType is missing and version is compatible)
        whenever(callbackMock.error(any(), any())).thenReturn(Response.status(Response.Status.BAD_REQUEST).build())

        // If we expect success, we must mock the downstream calls that happen after version check
        if (!expectError) {
            val mockJwtContext = mock<JwtContext>()
            
            // Mock the result of fetchIdToken
            doReturn(mockJwtContext).whenever(certificateService).fetchIdToken(any(), any())
            
            // Mock the jwtClaims property of JwtContext. 
            // Since the internal type of jwtClaims might be tricky, we mock the return to be a mock itself.
            whenever(mockJwtContext.jwtClaims).thenReturn(mock()) 
        }

        val userAgent = "authenticator/$requestVersion gematik/!"

        // act
        underTest.result(
            CODE, state, cardType, null, null, null, null, userAgent
        )

        // assert
        if (expectError) {
            verify(authSessionMock).setAuthNote(eq("error"), eq(AuthenticatorErrorTypes.UNSUPPORTED_AUTHENTICATOR_VERSION.error))
            verify(authSessionMock).setAuthNote(eq("error_details"), eq(minVersion))
        } else {
            verify(authSessionMock, never()).setAuthNote(eq("error"), eq(AuthenticatorErrorTypes.UNSUPPORTED_AUTHENTICATOR_VERSION.error))
        }
    }
}
