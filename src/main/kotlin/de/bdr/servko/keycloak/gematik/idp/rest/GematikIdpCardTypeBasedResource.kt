/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.model.*
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpCertificateService
import de.bdr.servko.keycloak.gematik.idp.util.*
import jakarta.ws.rs.GET
import jakarta.ws.rs.HeaderParam
import jakarta.ws.rs.Path
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriBuilder
import org.keycloak.OAuth2Constants
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.util.JsonSerialization
import java.net.URI


abstract class GematikIdpCardTypeBasedResource : GematikIDPResource() {
    abstract val certificateService: GematikIdpCertificateService
    abstract val flowLastStep: GematikIDPStep

    open fun handleHbaResult(authSession: AuthenticationSessionModel, encodedState: String?, code: String): Response =
        storeClaimsAndStartNextStep(authSession, code, AuthenticationCardType.HBA) { redirectToNextStep(encodedState) }

    open fun handleSmcbResult(authSession: AuthenticationSessionModel, encodedState: String?, code: String): Response =
        storeClaimsAndStartNextStep(authSession, code, AuthenticationCardType.SMCB) { redirectToNextStep(encodedState) }

    abstract fun finalizeLogin(authSession: AuthenticationSessionModel): Response

    fun storeClaimsAndStartNextStep(
        authSession: AuthenticationSessionModel,
        code: String,
        cardType: AuthenticationCardType,
        redirectToNextStep: () -> Response,
    ): Response {
        getClaimsMap(authSession, code, cardType)?.let {
            storeClaimsMapInSession(authSession, cardType, it)
        } ?: return getUnauthorizedResponse(cardType)
        return redirectToNextStep()
    }

    private fun redirectToNextStep(encodedState: String?): Response = encodedState?.let { state ->
        val authenticatorNextStepUrl = GematikIDPUtil.getEndpointUri(
            session,
            realm,
            GematikIDPState.fromEncodedState(state),
            config,
            GematikIdpLiterals.AUTHENTICATOR_NEXT_STEP
        )
        Response.seeOther(authenticatorNextStepUrl).build()
    } ?: Response.ok().type(MediaType.APPLICATION_JSON_TYPE).build()

    /**
     * Called by the browser to check the current status of the login process. Used as part of the new authentication
     * flow of the Gematik-Authenticator version 4.0 and above.
     * Returns 202, while Authenticator is processing.
     * Returns 200, after successful Authenticator call.
     */
    @GET
    @Path(GematikIdpLiterals.AUTHENTICATION_STATUS)
    override fun status(
        @QueryParam(OAuth2Constants.STATE) encodedState: String,
    ): Response {
        val authenticatorNextStepUrl = GematikIDPUtil.getEndpointUri(
            session, realm,
            GematikIDPState.fromEncodedState(encodedState), config,
            GematikIdpLiterals.AUTHENTICATOR_NEXT_STEP
        )
        return withAuthSessionAndLoginTimeout(
            encodedState,
            onSessionNotFound = { respondWithStatusRedirect(GematikIDPStep.ERROR.name, authenticatorNextStepUrl) }
        ) { authSession ->
            when (val step = GematikIDPUtil.getGematikIdpStepFrom(authSession)) {
                flowLastStep, GematikIDPStep.ERROR -> {
                    respondWithStatusRedirect(step.name, authenticatorNextStepUrl)
                }

                else -> {
                    Response.status(Response.Status.ACCEPTED).entity(
                        GematikIDPStatusResponse(
                            GematikIDPStep.WAITING_FOR_AUTHENTICATOR_RESPONSE.name, null
                        )
                    ).build()
                }
            }
        }
    }

    /**
     * Wrapper for the next authenticator step to show an error page without diverting from the legacy authentication
     * flow.
     */
    @GET
    @Path(GematikIdpLiterals.AUTHENTICATOR_NEXT_STEP)
    override fun nextStep(
        @QueryParam(OAuth2Constants.STATE) encodedState: String,
    ): Response = withAuthSessionAndLoginTimeout(encodedState) { authSession ->
        when (val step = GematikIDPUtil.getGematikIdpStepFrom(authSession)) {
            GematikIDPStep.ERROR -> {
                handleAuthenticatorError(authSession)
            }

            flowLastStep -> {
                finalizeLogin(authSession)
            }

            else -> {
                handleInternalErrorWhenCalledFromBrowser(
                    AuthenticatorErrorTypes.NON_FINAL_STEP,
                    "Authentication is still in progress. Current step is $step. Please try again later.",
                    Response.Status.PRECONDITION_REQUIRED
                )
            }
        }
    }

    /**
     * This is called in the multi, HBA and SMCB authentication flows by the Gematik-Authenticator.
     * When called via the Gematik-Authenticator, we need to resolve the authentication session using the encoded state
     * via the root authentication session.
     */
    @GET
    @Path(GematikIdpLiterals.RESULT_PATH)
    override fun result(
        @QueryParam(OAuth2Constants.CODE) code: String?,
        @QueryParam(OAuth2Constants.STATE) encodedState: String?,
        @QueryParam(GematikIdpLiterals.CARD_TYPE) cardType: String?,
        @QueryParam(GematikIdpLiterals.ERROR) error: String?,
        @QueryParam(GematikIdpLiterals.ERROR_DETAILS) errorDetails: String?,
        @QueryParam(GematikIdpLiterals.ERROR_DESCRIPTION) errorDescription: String?,
        @QueryParam(GematikIdpLiterals.ERROR_URI) errorUri: String?,
        @HeaderParam(HttpHeaders.USER_AGENT) userAgent: String?,
    ): Response {

        val errorMessage = errorDetails ?: errorDescription
        if (code.isNullOrEmpty() && encodedState.isNullOrEmpty()) {
            return handleErrorWhenCalledFromBrowser(error, errorMessage, errorUri)
        }
        return withAuthSessionAndLoginTimeout(encodedState!!) { authSession ->
            val version = authSession.getAuthenticatorVersionAuthNote()
                .takeIf { !it.isNullOrBlank() }
                ?.let(AuthenticatorVersion::from)
                ?: VersionFromUserAgentReader.readVersionFrom(userAgent)
            GematikIDPUtil.addAuthenticatorVersionToMdc(version)

            val newAuthenticatorVersion = GematikIDPUtil.isNewAuthenticatorFlow(authSession, version, realm)
            val errorResponse = getAuthenticatorErrorResponse(
                authSession,
                error,
                errorMessage,
                errorUri,
                version,
                cardType,
                newAuthenticatorVersion
            )
            errorResponse ?: run {
                if (!version.isNullOrEmpty()) {
                    authSession.setAuthenticatorVersionAuthNote(version.toString())
                }
                val encodedStateToPass = encodedState.takeIf { newAuthenticatorVersion }
                when (cardType) {
                    AuthenticationCardType.HBA.typeName ->
                        handleHbaResult(authSession, encodedStateToPass, code!!)

                    AuthenticationCardType.SMCB.typeName ->
                        handleSmcbResult(authSession, encodedStateToPass, code!!)

                    else -> callback.error(config, "invalid step for code $encodedState")
                }
            }
        }
    }

    private fun getAuthenticatorErrorResponse(
        authSession: AuthenticationSessionModel,
        error: String?,
        errorDetails: String?,
        errorUri: String?,
        version: AuthenticatorVersion?,
        cardType: String?,
        newAuthenticatorVersion: Boolean,
    ): Response? {
        var errorResponse: Response? = null
        if (!error.isNullOrBlank() || !errorDetails.isNullOrBlank() || !errorUri.isNullOrBlank()) {
            errorResponse = if (error == GematikIdpLiterals.CONSENT_DECLINED_ERROR &&
                errorDetails == GematikIdpLiterals.CONSENT_DECLINED_ERROR_DETAIL
            ) {
                ErrorUtils.saveConsentDeclined(authSession)
            } else {
                ErrorUtils.saveIdpErrorInAuthSession(
                    authSession, error, errorDetails, errorUri
                )
            }
        }
        if (errorResponse == null && !verifyVersionCompatibility(version)) {
            errorResponse =
                ErrorUtils.saveUnsupportedAuthenticatorVersion(authSession, config.getAuthenticatorVersion())
        }

        return if (newAuthenticatorVersion && errorResponse != null) {
            handleAuthenticatorError(authSession)
        } else errorResponse
    }

    private fun handleAuthenticatorError(authSession: AuthenticationSessionModel): Response {
        val error: String? = authSession.getAuthNote(GematikIdpLiterals.ERROR)
        val errorDetails: String? = authSession.getAuthNote(GematikIdpLiterals.ERROR_DETAILS)
        val errorUri: String? = authSession.getAuthNote(GematikIdpLiterals.ERROR_URI)
        return handleErrorWhenCalledFromBrowser(error, errorDetails, errorUri)
    }

    /**
     * Generate status url for the new flow.
     */
    override fun probeAuthenticatorServerUrl(authenticatorPort: Int): URI =
        UriBuilder.fromUri("$LOCALHOST$authenticatorPort$STATUS_ENDPOINT").build()

    fun getClaimsMap(
        authSession: AuthenticationSessionModel,
        code: String,
        cardType: AuthenticationCardType,
    ): MutableMap<String, Any>? {
        val codeVerifier: String = authSession.getCodeVerifierAuthNote() ?: return null
        val idToken = certificateService.fetchIdToken(codeVerifier, code)
        val claimsMap = idToken.jwtClaims.claimsMap ?: return null
        logger.debug("${cardType.typeName}-DATA: ${claimsMap.map { (k, v) -> "$k:$v\n" }}")
        return claimsMap
    }

    fun storeClaimsMapInSession(
        authSession: AuthenticationSessionModel,
        cardType: AuthenticationCardType,
        claimsMap: MutableMap<String, Any>,
    ) {
        when (cardType) {
            AuthenticationCardType.SMCB -> {
                authSession.setAuthNote(
                    GematikIdpLiterals.SMCB_DATA,
                    JsonSerialization.writeValueAsString(claimsMap)
                )
                authSession.setGematikIDPStepAuthNote(GematikIDPStep.RECEIVED_SMCB_DATA.name)
            }

            AuthenticationCardType.HBA -> {
                authSession.setAuthNote(
                    GematikIdpLiterals.HBA_DATA,
                    JsonSerialization.writeValueAsString(claimsMap)
                )
                authSession.setGematikIDPStepAuthNote(GematikIDPStep.RECEIVED_HBA_DATA.name)
            }
        }
    }

    private fun verifyVersionCompatibility(version: AuthenticatorVersion?): Boolean =
        version?.isGreaterThenOrEqual(AuthenticatorVersion.from(config.getAuthenticatorVersion())) ?: false

}
