/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.GematikIDP
import de.bdr.servko.keycloak.gematik.idp.TestUtils
import de.bdr.servko.keycloak.gematik.idp.extension.BrainpoolCurves
import de.bdr.servko.keycloak.gematik.idp.model.*
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpCertificateService
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals.Companion.AUTHENTICATOR_PORT
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals.Companion.CODE_VERIFIER
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals.Companion.HANDSHAKE_ID
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals.Companion.LOGIN_START_TIME_NOTE
import jakarta.ws.rs.core.Response
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.junit.jupiter.params.provider.NullAndEmptySource
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.forms.login.freemarker.model.ClientBean
import org.mockito.ArgumentMatchers
import org.mockito.kotlin.*
import java.net.URI

internal class GematikIDPHbaResourceTest : GematikIDPEndpointBaseTest() {
    private var isHba = true

    private val certificateService = object : GematikIdpCertificateService(realmMock, sessionMock, config, rest) {
        override fun generateTokenKeyBytes(): ByteArray = if (isHba) {
            ("dg99COL1CfysxnBuUTxz4gjfNdtD6OoCca5sdKwdUSY=").decodeBase64()
        } else {
            ("zdztIiMMgVa3jKdvrNG04BtbTZ4TjbbziazVjLLmEbM=").decodeBase64()
        }

        override fun skipAllValidators(): Boolean = true
    }

    val idp = GematikIDP(sessionMock, config)

    private val underTest = GematikIDPHbaResource(
        realmMock, callbackMock, sessionMock, idp, config, service, formsMock, certificateService
    )

    @BeforeEach
    fun beforeEach() {
        CryptoIntegration.init(javaClass.classLoader)
        BrainpoolCurves.init()
        whenever(sessionMock.authenticationSessions()).thenReturn(authenticationSession)
        whenever(authenticationSession.getRootAuthenticationSession(realmMock, ROOT_SESSION_ID)).thenReturn(
                rootAuthenticationSession
            )
    }

    @Test
    fun `timeout - returns correct form response`() {
        // act
        underTest.timeout(state)

        // assert
        val capture = argumentCaptor<ClientBean>()
        verify(formsMock).setAttribute(eq("client"), capture.capture())
        val clientBean = capture.firstValue
        assertThat(clientBean.clientId).isEqualTo(CLIENT_ID)

        verify(formsMock).createForm("gematik-idp-timeout.ftl")
    }

    @Test
    fun `timeout - resolveAuthSession not found`() {
        testResolveAuthSessionNotFoundFailure {
            underTest.timeout(state)
        }
    }

    @Test
    fun `timeout - resolveAuthSession fails`() {
        testResolveAuthSessionFailure {
            underTest.timeout(state)
        }
    }

    @Test
    fun `startAuth - returns correct form response`() {
        // arrange
        assertThat(underTest.startAuth(state).statusInfo).isEqualTo(Response.Status.OK)

        val authenticatorUrlCaptor = argumentCaptor<URI>()

        verify(formsMock).setAttribute(eq("authenticatorUrl"), authenticatorUrlCaptor.capture())
        val authenticatorUrl = authenticatorUrlCaptor.firstValue
        assertAuthenticatorUrl(authenticatorUrl, "HBA")

        verify(formsMock).setAttribute(
            "timeoutUrl",
            URI.create("http://localhost:8080/realms/$REALM_NAME/broker/$IDP_ALIAS/endpoint/timeout?state=$state")
        )
        verify(formsMock).setAttribute(
            "statusUrl",
            URI.create("http://localhost:8080/realms/$REALM_NAME/broker/$IDP_ALIAS/endpoint/status?state=$state")
        )
        verify(formsMock).setAttribute("timeoutMs", 20000)
        verify(formsMock).setAttribute("authenticatorAutoLaunch", true)
        verify(formsMock).createForm("gematik-idp.ftl")
        verify(authSessionMock).setAuthNote("GEMATIK_IDP_STEP", "REQUESTED_HBA_DATA")
    }

    @Test
    fun `startAuth - returns correct form response with port and handshake_id`() {
        whenever(authSessionMock.getAuthNote(AUTHENTICATOR_PORT)).thenReturn("1234")
        whenever(authSessionMock.getAuthNote(HANDSHAKE_ID)).thenReturn("vg3xs")

        // arrange
        assertThat(underTest.startAuth(state).statusInfo).isEqualTo(Response.Status.OK)

        val authenticatorUrlCaptor = argumentCaptor<URI>()

        verify(formsMock).setAttribute(eq("authenticatorUrl"), authenticatorUrlCaptor.capture())
        val authenticatorUrl = authenticatorUrlCaptor.firstValue
        assertAuthenticatorUrl(authenticatorUrl, "HBA")

        verify(formsMock).setAttribute(
            "timeoutUrl",
            URI.create("http://localhost:8080/realms/$REALM_NAME/broker/$IDP_ALIAS/endpoint/timeout?state=$state")
        )
        verify(formsMock).setAttribute(
            "authRequestUrl",
            URI.create("http://localhost:8080/realms/$REALM_NAME/broker/$IDP_ALIAS/endpoint/authRequest?state=$state")
        )
        verify(formsMock).setAttribute(
            "statusUrl",
            URI.create("http://localhost:8080/realms/$REALM_NAME/broker/$IDP_ALIAS/endpoint/status?state=$state")
        )
        verify(formsMock).setAttribute(
            "probeAuthenticatorServerUrl",
            URI.create("http://localhost:1234/status")
        )

        verify(formsMock).setAttribute("authenticatorPortRangeStart", 1024)
        verify(formsMock).setAttribute("authenticatorPortRangeEnd", 65535)
        verify(formsMock).setAttribute("timeoutMs", 20000)
        verify(formsMock).setAttribute("authenticatorHttpServerTimeoutMs", 10000)
        verify(formsMock).setAttribute("authenticatorAutoLaunch", true)
        verify(formsMock).createForm("gematik-idp.ftl")
        verify(authSessionMock).setAuthNote("GEMATIK_IDP_STEP", "REQUESTED_HBA_DATA")
    }

    @Test
    fun `startAuth - missing authenticatorPort returns bad request`() {
        // arrange: make the auth note for authenticatorPort missing
        whenever(authSessionMock.getAuthNote(AUTHENTICATOR_PORT)).thenReturn(null)

        // act
        val response = underTest.startAuth(state)

        // assert
        assertThat(response.statusInfo).isEqualTo(Response.Status.BAD_REQUEST)
        // The response entity should contain the error message
        assertThat(response.entity).isEqualTo("Missing authenticatorPort")
        // Ensure no form page is created
        verify(formsMock, never()).createForm(any())
    }

    @Test
    fun `startAuth - returns timeout response`() {

        // arrange
        val startTime = System.currentTimeMillis().minus(62000).toString()
        whenever(authSessionMock.getAuthNote(LOGIN_START_TIME_NOTE)).thenReturn(startTime)

        // assert
        assertThat(underTest.startAuth(state).statusInfo).isEqualTo(Response.Status.BAD_REQUEST)
        verify(formsMock).createErrorPage(Response.Status.BAD_REQUEST)
        verify(formsMock).setError("loginTimeout","Login timeout. Please log in again.")
    }

    @Test
    fun `authRequest - returns correct response`() {
        whenever(authSessionMock.getAuthNote(HANDSHAKE_ID)).thenReturn("gt3kj6")
        whenever(authSessionMock.getAuthNote(AUTHENTICATOR_PORT)).thenReturn("1234")
        whenever(authSessionMock.getAuthNote(CODE_VERIFIER)).thenReturn("1234")

        val response = underTest.authRequest(state, "4.17.1")
        assertThat(response.status).isEqualTo(303)
        assertThat(response.location).isNotNull
        assertAuthorizeUrl(response.location, CardType.HBA.name)
    }

    @Test
    fun `authRequest - returns timeout response`() {
        // arrange
        val startTime = System.currentTimeMillis().minus(62000).toString()
        whenever(authSessionMock.getAuthNote(LOGIN_START_TIME_NOTE)).thenReturn(startTime)

        // assert
        assertThat(underTest.authRequest(state, "4.17.1").statusInfo).isEqualTo(Response.Status.BAD_REQUEST)
        verify(formsMock).createErrorPage(Response.Status.BAD_REQUEST)
        verify(formsMock).setError("loginTimeout","Login timeout. Please log in again.")
    }

    @Test
    fun `authRequest - resolveAuthSession not found`() {
        testResolveAuthSessionNotFoundStatusEndpointFailure {
            underTest.authRequest(state, "4.17.1")
        }
    }

    @Test
    fun `authRequest - resolveAuthSession fails`() {
        testResolveAuthSessionFailure {
            underTest.authRequest(state, "4.17.1")
        }
    }

    @ParameterizedTest
    @EnumSource(
        value = GematikIDPStep::class,
        names = ["RECEIVED_SMCB_DATA", "REQUESTED_HBA_DATA", "REQUESTED_SMCB_DATA", "WAITING_FOR_AUTHENTICATOR_RESPONSE"]
    )
    fun `status - Current step is non-final - Return Accepted`(step: GematikIDPStep) {
        // arrange
        whenever(authSessionMock.getAuthNote("HBA_DATA")).thenReturn(TestUtils.getJsonHbaToken())
        whenever(authSessionMock.getAuthNote("SMCB_DATA")).thenReturn(null)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP")).thenReturn(step.name)

        // act
        val result = underTest.status(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.ACCEPTED)
        assertThat((result.entity as GematikIDPStatusResponse).currentStep).isEqualTo(GematikIDPStep.WAITING_FOR_AUTHENTICATOR_RESPONSE.name)
    }

    @ParameterizedTest
    @EnumSource(
        value = GematikIDPStep::class,
        names = ["RECEIVED_HBA_DATA", "ERROR"]
    )
    fun `status - Current step is final - Return Accepted`(step: GematikIDPStep) {
        // arrange
        whenever(authSessionMock.getAuthNote("HBA_DATA")).thenReturn(TestUtils.getJsonHbaToken())
        whenever(authSessionMock.getAuthNote("SMCB_DATA")).thenReturn(null)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP")).thenReturn(step.name)

        // act
        val result = underTest.status(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.OK)
        assertThat((result.entity as GematikIDPStatusResponse).currentStep).isEqualTo(step.name)
        assertNextStepUrl((result.entity as GematikIDPStatusResponse).nextStepUrl!!)
    }

    @Test
    fun `status - Current step is null - error`() {
        // arrange
        whenever(authSessionMock.getAuthNote("HBA_DATA")).thenReturn(null)
        whenever(authSessionMock.getAuthNote("SMCB_DATA")).thenReturn(null)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP")).thenReturn(null)

        // act
        val result = underTest.status(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.OK)
        assertThat((result.entity as GematikIDPStatusResponse).currentStep).isEqualTo(GematikIDPStep.ERROR.name)
        assertNextStepUrl((result.entity as GematikIDPStatusResponse).nextStepUrl!!)
    }

    @Test
    fun `status - resolveAuthSession not found`() {
        testResolveAuthSessionNotFoundStatusEndpointFailure {
            underTest.status(state)
        }
    }

    @Test
    fun `status - resolveAuthSession fails`() {
        testResolveAuthSessionFailure {
            underTest.status(state)
        }
    }

    @Test
    fun `status - returns timeout response`() {

        // arrange
        val startTime = System.currentTimeMillis().minus(62000).toString()
        whenever(authSessionMock.getAuthNote(LOGIN_START_TIME_NOTE)).thenReturn(startTime)

        // assert
        assertThat(underTest.status(state).statusInfo).isEqualTo(Response.Status.BAD_REQUEST)
        verify(formsMock).createErrorPage(Response.Status.BAD_REQUEST)
        verify(formsMock).setError("loginTimeout","Login timeout. Please log in again.")
    }

    @Test
    fun `nextStep - idp error saved in auth session`() {
        // arrange
        val error = "invalid_scope"
        val errorDetails = "AUTHCL_0001"
        val errorUri = "https://wiki.gematik.de/pages/viewpage.action?pageId=466488828"

        whenever(formsMock.createErrorPage(Response.Status.BAD_REQUEST)).thenReturn(
            Response.status(Response.Status.BAD_REQUEST).build())

        whenever(authSessionMock.getAuthNote("error")).thenReturn(error)
        whenever(authSessionMock.getAuthNote("error_details")).thenReturn(errorDetails)
        whenever(authSessionMock.getAuthNote("error_uri")).thenReturn(errorUri)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPStep.ERROR.name)

        // act
        val result = underTest.nextStep(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.BAD_REQUEST)

        verify(formsMock).setError(
            eq("authenticator.errorIdp"),
            eq(errorDetails)
        )
    }

    @ParameterizedTest
    @EnumSource(
        value = GematikIDPStep::class,
        names = ["REQUESTED_HBA_DATA", "REQUESTED_SMCB_DATA", "RECEIVED_SMCB_DATA", "WAITING_FOR_AUTHENTICATOR_RESPONSE"]
    )
    fun `nextStep - Non-final step results in error`(step: GematikIDPStep) {
        // arrange
        val error = "Authentication is still in progress. Current step is $step. Please try again later."

        whenever(formsMock.createErrorPage(Response.Status.PRECONDITION_REQUIRED)).thenReturn(
            Response.status(Response.Status.PRECONDITION_REQUIRED).build())

        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(step.name)

        // act
        val result = underTest.nextStep(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.PRECONDITION_REQUIRED)

        verify(formsMock).setError(eq("authenticator.nonFinalStep"), eq(error))
    }

    @Test
    fun `nextStep - HBA data saved in auth session`() {
        // arrange
        whenever(authSessionMock.getAuthNote("HBA_DATA")).thenReturn(TestUtils.getHbaData())
        whenever(authSessionMock.getAuthNote("SMCB_DATA")).thenReturn(null)
        whenever(authSessionMock.getAuthNote("CODE_VERIFIER")).thenReturn(hbaKeyVerifier)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPStep.RECEIVED_HBA_DATA.name)
        whenever(callbackMock.authenticated(any())).thenReturn(Response.ok().build())

        // act
        val result = underTest.nextStep(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.OK)

        val identityCapture = argumentCaptor<BrokeredIdentityContext>()
        verify(callbackMock).authenticated(identityCapture.capture())
        val identityContext = identityCapture.firstValue

        val hbaTelematikID = "1-HBA-Testkarte-883110000129083"
        assertThat(identityContext.id).startsWith(hbaTelematikID)
        assertThat(identityContext.username).isEqualTo(hbaTelematikID)
        assertThat(identityContext.modelUsername).isEqualTo(hbaTelematikID)

        val contextData = identityContext.contextData
        assertThat(contextData).hasSize(9)
        assertThat(contextData[ContextData.CONTEXT_HBA_TELEMATIK_ID.name]).isEqualTo(hbaTelematikID)
        assertThat(contextData[ContextData.CONTEXT_HBA_PROFESSION_OID.name]).isEqualTo("1.2.276.0.76.4.30")
        assertThat(contextData[ContextData.CONTEXT_HBA_GIVEN_NAME.name]).isEqualTo("Roland")
        assertThat(contextData[ContextData.CONTEXT_HBA_FAMILY_NAME.name]).isEqualTo("MaiÞer")
        assertThat(contextData[ContextData.CONTEXT_SMCB_TELEMATIK_ID.name]).isEqualTo("UNKNOWN")
        assertThat(contextData[ContextData.CONTEXT_SMCB_PROFESSION_OID.name]).isEqualTo("UNKNOWN")
        assertThat(contextData[ContextData.CONTEXT_SMCB_ORGANIZATION_NAME.name]).isEqualTo("UNKNOWN")
        assertThat(contextData[ContextData.CONTEXT_SMCB_GIVEN_NAME.name]).isEqualTo("UNKNOWN")
        assertThat(contextData[ContextData.CONTEXT_SMCB_FAMILY_NAME.name]).isEqualTo("UNKNOWN")
    }

    @Test
    fun `nextStep - Final step, but no HBA data saved in auth session`() {
        // arrange
        val error = "Tried to finalize login without complete authentication"

        whenever(authSessionMock.getAuthNote("HBA_DATA")).thenReturn(null)
        whenever(authSessionMock.getAuthNote("SMCB_DATA")).thenReturn(null)
        whenever(authSessionMock.getAuthNote("CODE_VERIFIER")).thenReturn(hbaKeyVerifier)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP"))
            .thenReturn(GematikIDPStep.RECEIVED_HBA_DATA.name)
        whenever(callbackMock.authenticated(any())).thenReturn(Response.ok().build())

        whenever(formsMock.createErrorPage(Response.Status.BAD_REQUEST)).thenReturn(
            Response.status(Response.Status.BAD_REQUEST).build())

        // act
        val result = underTest.nextStep(state)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.BAD_REQUEST)

        verify(formsMock)
            .setError(eq("authenticator.incompleteIdpData"), eq(error))
    }

    @Test
    fun `nextStep - resolveAuthSession not found`() {
        testResolveAuthSessionNotFoundFailure {
            underTest.nextStep(state)
        }
    }

    @Test
    fun `nextStep - resolveAuthSession fails`() {
        testResolveAuthSessionFailure {
            underTest.nextStep(state)
        }
    }

    @Test
    fun `nextStep - returns timeout response`() {

        // arrange
        val startTime = System.currentTimeMillis().minus(62000).toString()
        whenever(authSessionMock.getAuthNote(LOGIN_START_TIME_NOTE)).thenReturn(startTime)

        // assert
        assertThat(underTest.nextStep(state).statusInfo).isEqualTo(Response.Status.BAD_REQUEST)
        verify(formsMock).createErrorPage(Response.Status.BAD_REQUEST)
        verify(formsMock).setError("loginTimeout","Login timeout. Please log in again.")
    }

    @Test
    fun `result resolveAuthSession not found`() {
        testResolveAuthSessionNotFoundFailure {
            underTest.result("", state)
        }
    }

    @Test
    fun `result - resolveAuthSession fails`() {
        testResolveAuthSessionFailure {
            underTest.result("", state)
        }
    }

    @Test
    fun `result - function call with error`() {
        // arrange
        val error = "invalid_request"
        val errorDetails = "client_id ist ungültig"
        val errorUri = "https://wiki.gematik.de/x/-A3OGw"

        whenever(callbackMock.error(eq(config), ArgumentMatchers.anyString())).
            thenReturn(Response.status(Response.Status.NO_CONTENT).build())

        // act
        val result = underTest.result(CODE, state, null, error, errorDetails, errorUri)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.NO_CONTENT)
        verify(authSessionMock).setAuthNote("error", error)
        verify(authSessionMock).setAuthNote("error_details", errorDetails)
        verify(authSessionMock).setAuthNote("error_uri", errorUri)
        verify(authSessionMock).setAuthNote("GEMATIK_IDP_STEP", GematikIDPStep.ERROR.name)
    }

    @Test
    fun `result - function call with authenticator consent error`() {
        // arrange
        val error = "access_denied"
        val errorDetails = "User declined consent"

        whenever(callbackMock.error(eq(config), ArgumentMatchers.anyString())).
            thenReturn(Response.status(Response.Status.NO_CONTENT).build())

        // act
        val result = underTest.result(CODE, state, null, error, errorDetails)

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.NO_CONTENT)
        verify(authSessionMock).setAuthNote("error", AuthenticatorErrorTypes.CONSENT_DECLINED.error)
        verify(authSessionMock)
            .setAuthNote("error_details", "User declined consent. Please start again and give your consent.")
        verify(authSessionMock).setAuthNote("error_uri", null)
        verify(authSessionMock).setAuthNote("GEMATIK_IDP_STEP", GematikIDPStep.ERROR.name)
    }

    @Test
    fun `result - function call with authenticator version error`() {
        // arrange
        isHba = true

        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP")).thenReturn(GematikIDPStep.REQUESTED_HBA_DATA.name)
        whenever(authSessionMock.getAuthNote("CODE_VERIFIER")).thenReturn(hbaKeyVerifier)

        val error = "authenticator.unsupportedAuthenticatorVersion"
        val errorDetails = "Authenticator version unsupported. Please update your Authenticator."

        // act
        val result = underTest.result(CODE, state, "HBA", null, null, null, "authenticator/4.5.0 gematik/!")

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.NO_CONTENT)
        verify(authSessionMock).setAuthNote("error", error)
        verify(authSessionMock).setAuthNote("error_details", errorDetails)
        verify(authSessionMock).setAuthNote("error_uri", null)
        verify(authSessionMock).setAuthNote("GEMATIK_IDP_STEP", GematikIDPStep.ERROR.name)
    }

    @Test
    fun `result - returns timeout response`() {

        // arrange
        val startTime = System.currentTimeMillis().minus(62000).toString()
        whenever(authSessionMock.getAuthNote(LOGIN_START_TIME_NOTE)).thenReturn(startTime)

        // assert
        assertThat(underTest.result("", state).statusInfo).isEqualTo(Response.Status.BAD_REQUEST)
        verify(formsMock).createErrorPage(Response.Status.BAD_REQUEST)
        verify(formsMock).setError("loginTimeout","Login timeout. Please log in again.")
    }

    @ParameterizedTest
    @NullAndEmptySource
    fun `result - no or empty card type - corresponding error is set`(cardType: String?) {
        // arrange
        isHba = true

        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP")).thenReturn(GematikIDPStep.REQUESTED_HBA_DATA.name)
        whenever(authSessionMock.getAuthNote("CODE_VERIFIER")).thenReturn(hbaKeyVerifier)

        val error = "authenticator.unsupportedAuthenticatorVersion"
        val errorDetails = "Authenticator version unsupported. Please update your Authenticator."
        val errorUri = null

        whenever(authSessionMock.getAuthNote("error")).thenReturn(error)
        whenever(authSessionMock.getAuthNote("error_details")).thenReturn(errorDetails)
        whenever(authSessionMock.getAuthNote("error_uri")).thenReturn(errorUri)
        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP")).thenReturn(GematikIDPStep.ERROR.name)

        whenever(callbackMock.error(eq(config), ArgumentMatchers.anyString())).thenReturn(
            Response.status(Response.Status.BAD_REQUEST).build()
        )

        // act
        val result = underTest.result(
            CODE,
            state,
            cardType,
        )

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.NO_CONTENT)
        verify(authSessionMock).setAuthNote("error", error)
        verify(authSessionMock).setAuthNote("error_details", errorDetails)
        verify(authSessionMock).setAuthNote("error_uri", errorUri)
        verify(authSessionMock).setAuthNote("GEMATIK_IDP_STEP", GematikIDPStep.ERROR.name)
    }

    @ParameterizedTest
    @NullAndEmptySource
    fun `result - no or empty code and state - corresponding error is set`(code: String?) {
        testAssertCodeAndStateNullOrEmpty {
            underTest.result(code, code)
        }
    }

    @Test
    fun `result - received HBA data successfully - data is saved in session`() {
        // arrange
        isHba = true

        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP")).thenReturn(GematikIDPStep.REQUESTED_HBA_DATA.name)
        whenever(authSessionMock.getAuthNote("CODE_VERIFIER")).thenReturn(hbaKeyVerifier)
        whenever(authSessionMock.getAuthNote("authenticatorVersion")).thenReturn(authenticatorVersion)

        mockDoGetJwk()
        mockDoPostToGetHbaToken()

        // act
        val result = underTest.result(
            CODE,
            state,
            "HBA",
            null,
            null,
            null,
            "authenticator/4.6.0 gematik/!"
        )

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.OK)
        verify(authSessionMock).setAuthNote("GEMATIK_IDP_STEP", GematikIDPStep.RECEIVED_HBA_DATA.name)
        verify(authSessionMock).setAuthNote(eq("HBA_DATA"), any())
    }

    @Test
    fun `result - received HBA data successfully - redirect to next step in new flow`() {
        // arrange
        isHba = true

        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP")).thenReturn(GematikIDPStep.REQUESTED_HBA_DATA.name)
        whenever(authSessionMock.getAuthNote("CODE_VERIFIER")).thenReturn(hbaKeyVerifier)
        whenever(authSessionMock.getAuthNote("authenticatorVersion")).thenReturn("4.17.1")

        mockDoGetJwk()
        mockDoPostToGetHbaToken()

        // act
        val result = underTest.result(
            CODE,
            state,
            "HBA",
            null,
            null,
            null,
            "4.17.1"
        )

        // assert
        assertThat(result.statusInfo.statusCode).isEqualTo(Response.Status.SEE_OTHER.statusCode)
        assertThat(result.location).isEqualTo(URI("http://localhost:8080/realms/test-realm/broker/gematik-idp/endpoint/nextStep?state=rootSessionId__gematik_client__tabId"))
        verify(authSessionMock).setAuthNote("GEMATIK_IDP_STEP", GematikIDPStep.RECEIVED_HBA_DATA.name)
        verify(authSessionMock).setAuthNote(eq("HBA_DATA"), any())
    }

    @Test
    fun `result - received SMC-B data successfully - error saved in session, because unsupported card type`() {
        // arrange
        isHba = false

        whenever(authSessionMock.getAuthNote("GEMATIK_IDP_STEP")).thenReturn(GematikIDPStep.REQUESTED_SMCB_DATA.name)
        whenever(authSessionMock.getAuthNote("CODE_VERIFIER")).thenReturn(smcbKeyVerifier)
        whenever(authSessionMock.getAuthNote("authenticatorVersion")).thenReturn(authenticatorVersion)

        val error = "authenticator.unsupportedCardType"
        val errorDetails = "Received SMC-B data, which is not configured for this flow."
        val errorUri = null

        // act
        val result = underTest.result(CODE,
            state,
            "SMC-B",
            null,
            null,
            null,
            "authenticator/4.6.0 gematik/!"
        )

        // assert
        assertThat(result.statusInfo).isEqualTo(Response.Status.NO_CONTENT)
        verify(authSessionMock).setAuthNote("error", error)
        verify(authSessionMock).setAuthNote("error_details", errorDetails)
        verify(authSessionMock).setAuthNote("error_uri", errorUri)
        verify(authSessionMock).setAuthNote("GEMATIK_IDP_STEP", GematikIDPStep.ERROR.name)
    }
}
