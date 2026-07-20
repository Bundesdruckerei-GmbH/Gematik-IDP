/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.model.*
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpCertificateService
import de.bdr.servko.keycloak.gematik.idp.util.*
import de.bdr.servko.keycloak.gematik.idp.util.GematikIDPUtil.Companion.isNewAuthenticatorFlow
import jakarta.ws.rs.GET
import jakarta.ws.rs.HeaderParam
import jakarta.ws.rs.Path
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriBuilder
import org.keycloak.OAuth2Constants
import org.keycloak.common.util.Base64Url
import org.keycloak.common.util.SecretGenerator
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.protocol.oidc.utils.PkceUtils
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.util.JsonSerialization
import java.net.URI


abstract class GematikIdpCardTypeBasedResource : GematikIDPResource() {
    abstract val certificateService: GematikIdpCertificateService
    abstract val flowLastStep: GematikIDPStep

    abstract fun handleHbaResult(authSession: AuthenticationSessionModel, encodedState: String?, code: String, cardType: String): Response

    abstract fun handleSmcbResult(authSession: AuthenticationSessionModel, encodedState: String?, code: String, cardType: String): Response

    abstract fun finalizeLogin(authSession: AuthenticationSessionModel): Response

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
        val authenticatorNextStepUrl = GematikIDPUtil.getEndpointUri(session, realm,
            GematikIDPState.fromEncodedState(encodedState), config,
            GematikIdpLiterals.AUTHENTICATOR_NEXT_STEP
        )
        return withAuthSession(
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
    ): Response = withAuthSession(encodedState) { authSession ->
        when (val step = GematikIDPUtil.getGematikIdpStepFrom(authSession)) {
            GematikIDPStep.ERROR -> {
                val error: String? = authSession.getAuthNote(GematikIdpLiterals.ERROR)
                val errorDetails: String? = authSession.getAuthNote(GematikIdpLiterals.ERROR_DETAILS)
                val errorUri: String? = authSession.getAuthNote(GematikIdpLiterals.ERROR_URI)

                handleErrorWhenCalledFromBrowser(error, errorDetails, errorUri)
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
        @QueryParam(GematikIdpLiterals.ERROR_URI) errorUri: String?,
        @HeaderParam(HttpHeaders.USER_AGENT) userAgent: String?,
    ): Response {
        if (code.isNullOrEmpty() && encodedState.isNullOrEmpty()) {
            return handleErrorWhenCalledFromBrowser(error, errorDetails, errorUri)
        }
        return withAuthSession(encodedState!!) { authSession ->
            val version = getAuthenticatorVersion(userAgent, authSession)
            val errorResponse = getAuthenticatorErrorResponse(authSession, error, errorDetails, errorUri, version, cardType)
            errorResponse ?: run {
                GematikIDPUtil.setAuthenticatorVersionInAuthSession(version, authSession)
                val encodedStateToPass = if (isNewAuthenticatorFlow(authSession)) {
                    encodedState
                } else null
                when (cardType) {
                    AuthenticationCardType.HBA.typeName ->
                        handleHbaResult(authSession, encodedStateToPass, code!!, cardType)
                    AuthenticationCardType.SMCB.typeName ->
                        handleSmcbResult(authSession, encodedStateToPass, code!!, cardType)
                    else -> callback.error(config, "invalid step for code $encodedState")
                }
            }
        }
    }

    private fun getAuthenticatorVersion(userAgent: String?, authSession: AuthenticationSessionModel) : AuthenticatorVersion {

        val version = authSession
            .getAuthNote(GematikIdpLiterals.AUTHENTICATOR_VERSION)
            .takeIf { !it.isNullOrBlank() }
            ?.let(AuthenticatorVersion::from)
            ?: VersionFromUserAgentReader.readVersionFrom(userAgent)

        GematikIDPUtil.addAuthenticatorVersionToMdc(version)
        return version
    }

    private fun getAuthenticatorErrorResponse(
        authSession: AuthenticationSessionModel,
        error: String?,
        errorDetails: String?,
        errorUri: String?,
        version: AuthenticatorVersion?,
        cardType: String?,
    ): Response? {

        if (!error.isNullOrBlank() || !errorDetails.isNullOrBlank() || !errorUri.isNullOrBlank()) {
            return if (error == GematikIdpLiterals.CONSENT_DECLINED_ERROR &&
                errorDetails == GematikIdpLiterals.CONSENT_DECLINED_ERROR_DETAIL
            ) {
                ErrorUtils.saveConsentDeclined(authSession)
            } else {
                ErrorUtils.saveIdpErrorInAuthSession(
                    authSession, error, errorDetails, errorUri
                )
            }
        }

        if (cardType.isNullOrBlank() || !verifyVersionCompatibility(version)) {
            return ErrorUtils.saveUnsupportedAuthenticatorVersion(authSession)
        }

        return null
    }

    /**
     * Generate the Authenticator url.
     * redirectUri is our Keycloak instance /auth/realms/<realm>/broker/gematik-cidp/endpoint/result
     * challengePath is the central IDP
     */
    override fun generateAuthenticatorUrl(
        encodedState: String,
        codeVerifier: String,
        cardType: String,
        authenticatorPort: String?,
        handShakeId: String?,
    ): URI {
        val redirectUri = GematikIDPUtil.getEndpointUri(
            session, realm, null, config, GematikIdpLiterals.RESULT_PATH
        )
        val challengePath = generateChallengePath(redirectUri, encodedState, codeVerifier, cardType, authenticatorPort, handShakeId)
        val uriBuilder = handleAuthenticatorProtocol()
            .queryParam(GematikIdpLiterals.CHALLENGE_PATH_PARAM, challengePath)
            .queryParam(GematikIdpLiterals.CALLBACK, GematikAuthenticatorCallbackType.DIRECT.simpleName())
        return uriBuilder.build()
    }

    /**
     * Generate authorize url for the new flow.
     * redirectUri is our Keycloak instance /auth/realms/<realm>/broker/gematik-cidp/endpoint/result
     * challengePath is the central IDP
     */
    override fun generateAuthorizeUrl(encodedState: String, codeVerifier: String, cardType: String, authenticatorPort: String, handShakeId: String): URI {
        val baseUrl = "$LOCALHOST$authenticatorPort$AUTHORIZE_ENDPOINT"
        val challengePath = getChallengePath(encodedState, codeVerifier, cardType)
        val uriBuilder = handleAuthorizeEndpoint(baseUrl).queryParam(
            GematikIdpLiterals.CHALLENGE_PATH_PARAM, challengePath
        ).queryParam(GematikIdpLiterals.CALLBACK, GematikAuthenticatorCallbackType.DIRECT.simpleName())
            .queryParam(GematikIdpLiterals.HANDSHAKE_ID, handShakeId)
        return uriBuilder.build()
    }

    /**
     * Generate status url for the new flow.
     */
    override fun probeAuthenticatorServerUrl(authenticatorPort: String): URI {
        val statusUrl = "$LOCALHOST$authenticatorPort$STATUS_ENDPOINT"
        val uriBuilder = handleAuthorizeEndpoint(statusUrl)
        return uriBuilder.build()
    }

    private fun getChallengePath(encodedState: String, codeVerifier: String, cardType: String): URI {
        val redirectUri = GematikIDPUtil.getEndpointUri(session, realm, null, config, GematikIdpLiterals.RESULT_PATH)
        return generateChallengePath(
            redirectUri, encodedState, codeVerifier, cardType, null, null
        )
    }

    private fun generateChallengePath(
        redirectUri: URI,
        encodedState: String,
        codeVerifier: String,
        cardType: String,
        authenticatorPort: String?,
        handShakeId: String?,
    ): URI = UriBuilder.fromUri(config.getAuthenticatorAuthorizationUrl())
        .queryParam(OAuth2Constants.CLIENT_ID, config.clientId)
        .queryParam(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.CODE)
        .queryParam(OAuth2Constants.REDIRECT_URI, redirectUri)
        .queryParam(OAuth2Constants.STATE, encodedState)
        .queryParam(GematikIdpLiterals.CARD_TYPE, cardType)
        .queryParam(OAuth2Constants.SCOPE, escapeScope(config.defaultScope.trim()))
        .queryParam(OAuth2Constants.CODE_CHALLENGE, PkceUtils.generateS256CodeChallenge(codeVerifier))
        .queryParam(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)
        .queryParam(OIDCLoginProtocol.NONCE_PARAM, Base64Url.encode(SecretGenerator.getInstance().randomBytes(16)))
        .apply {
            authenticatorPort?.let {
                queryParam(GematikIdpLiterals.SERVER_PORT_PARAMETER, authenticatorPort)
            }
            handShakeId?.let {
                queryParam(GematikIdpLiterals.HANDSHAKE_ID, handShakeId)
            }
        }
        .build()

    fun getClaimsMap(
        authSession: AuthenticationSessionModel,
        code: String,
        cardType: String,
    ): MutableMap<String, Any>? {
        val codeVerifier: String = authSession.getAuthNote(GematikIdpLiterals.CODE_VERIFIER) ?: return null
        val idToken = certificateService.fetchIdToken(codeVerifier, code)
        val claimsMap = idToken.jwtClaims.claimsMap
        logger.debug("$cardType-DATA: ${claimsMap.map { (k, v) -> "$k:$v\n" }}")
        return claimsMap
    }

    fun handleClaimsMap(authSession: AuthenticationSessionModel, code: String, cardType: String) {
        val claimsMap = getClaimsMap(authSession, code, cardType)
        when (cardType) {
            AuthenticationCardType.SMCB.typeName -> {
                authSession.setAuthNote(GematikIdpLiterals.SMCB_DATA, JsonSerialization.writeValueAsString(claimsMap))
                authSession.setAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP, GematikIDPStep.RECEIVED_SMCB_DATA.name)
            }
            AuthenticationCardType.HBA.typeName -> {
                authSession.setAuthNote(GematikIdpLiterals.HBA_DATA, JsonSerialization.writeValueAsString(claimsMap))
                authSession.setAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP, GematikIDPStep.RECEIVED_HBA_DATA.name)
            }
        }
    }

    private fun verifyVersionCompatibility(version: AuthenticatorVersion?): Boolean {
        return version?.isGreaterThenOrEqual(AuthenticatorVersion.from(config.getAuthenticatorVersion())) ?: false
    }
}
