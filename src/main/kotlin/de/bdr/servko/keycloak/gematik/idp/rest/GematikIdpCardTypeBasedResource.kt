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

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.model.*
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpCertificateService
import de.bdr.servko.keycloak.gematik.idp.util.ErrorUtils
import de.bdr.servko.keycloak.gematik.idp.util.GematikIDPUtil
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals
import de.bdr.servko.keycloak.gematik.idp.util.VersionFromUserAgentReader
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
import java.net.URI

abstract class GematikIdpCardTypeBasedResource: GematikIDPResource() {
    abstract val certificateService: GematikIdpCertificateService
    abstract val flowLastStep: GematikIDPStep

    abstract fun handleHbaResult(authSession: AuthenticationSessionModel, code: String, cardType: String): Response

    abstract fun handleSmcbResult(authSession: AuthenticationSessionModel, code: String, cardType: String): Response

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
        val authSession: AuthenticationSessionModel = try {
            service.resolveAuthSessionFromEncodedState(realm, encodedState)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        val authenticatorNextStepUrl = GematikIDPUtil.getEndpointUri(
            session,
            realm,
            GematikIDPState.fromEncodedState(encodedState),
            config,
            GematikIdpLiterals.AUTHENTICATOR_NEXT_STEP
        )

        return when (val step = GematikIDPUtil.getGematikIdpStepFrom(authSession)) {
            flowLastStep, GematikIDPStep.ERROR -> {
                Response.ok().entity(
                    GematikIDPStatusResponse(
                        step.name, authenticatorNextStepUrl
                    )
                ).build()
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

    /**
     * Wrapper for the next authenticator step to show an error page without diverting from the legacy authentication
     * flow.
     */
    @GET
    @Path(GematikIdpLiterals.AUTHENTICATOR_NEXT_STEP)
    override fun nextStep(
        @QueryParam(OAuth2Constants.STATE) encodedState: String,
    ): Response {
        val authSession: AuthenticationSessionModel = try {
            service.resolveAuthSessionFromEncodedState(realm, encodedState)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        return when (val step = GematikIDPUtil.getGematikIdpStepFrom(authSession)) {
            GematikIDPStep.ERROR -> {
                val error = authSession.getAuthNote(GematikIdpLiterals.ERROR)
                val errorDetails = authSession.getAuthNote(GematikIdpLiterals.ERROR_DETAILS)
                val errorUri = authSession.getAuthNote(GematikIdpLiterals.ERROR_URI)

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
        val version = VersionFromUserAgentReader.readVersionFrom(userAgent)
        GematikIDPUtil.addAuthenticatorVersionToMdc(version)

        if (code == null && encodedState == null) {
            return handleErrorWhenCalledFromBrowser(error, errorDetails, errorUri)
        }

        val authSession: AuthenticationSessionModel = try {
            service.resolveAuthSessionFromEncodedState(realm, encodedState!!)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        if (error != null || errorDetails != null || errorUri != null) {
            return ErrorUtils.saveIdpErrorInAuthSession(authSession, error, errorDetails, errorUri)
        }

        if (cardType.isNullOrEmpty() || !verifyVersionCompatibility(version)) {
            return ErrorUtils.saveUnsupportedAuthenticatorVersion(authSession)
        }

        GematikIDPUtil.setAuthenticatorVersionInAuthSession(version, authSession)
        return when (cardType) {
            AuthenticationCardType.HBA.typeName -> {
                handleHbaResult(authSession, code!!, cardType)
            }

            AuthenticationCardType.SMCB.typeName -> {
                handleSmcbResult(authSession, code!!, cardType)
            }

            else -> {
                callback.error("invalid step for code $encodedState")
            }
        }
    }

    /**
     * Generate the Authenticator url.
     * redirectUri is our Keycloak instance /auth/realms/<realm>/broker/gematik-cidp/endpoint/result
     * [de.bdr.servko.keycloak.gematik.idp.rest.GematikIDPLegacyEndpoint.resultPost]
     * challengePath is the central IDP
     */
    override fun generateAuthenticatorUrl(encodedState: String, codeVerifier: String, cardType: String): URI {
        val redirectUri = GematikIDPUtil.getEndpointUri(
            session, realm, null, config, GematikIdpLiterals.RESULT_PATH
        )
        val challengePath = generateChallengePath(
            redirectUri, encodedState, codeVerifier, cardType
        )
        val uriBuilder = handleAuthenticatorProtocol().queryParam(
            GematikIdpLiterals.CHALLENGE_PATH, challengePath
        ).queryParam(GematikIdpLiterals.CALLBACK, GematikAuthenticatorCallbackType.DIRECT.simpleName())

        return uriBuilder.build()
    }

    private fun generateChallengePath(
        redirectUri: URI,
        encodedState: String,
        codeVerifier: String,
        cardType: String,
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
        .build()

    fun getClaimsMap(
        authSession: AuthenticationSessionModel,
        code: String,
        cardType: String,
    ): MutableMap<String, Any>? {
        val codeVerifier = authSession.getAuthNote(GematikIdpLiterals.CODE_VERIFIER)
        val idToken = certificateService.fetchIdToken(codeVerifier, code)

        val claimsMap = idToken.jwtClaims.claimsMap

        logger.debug("$cardType-DATA: ${claimsMap.map { (k, v) -> "$k:$v\n" }}")
        return claimsMap
    }

    private fun verifyVersionCompatibility(version: AuthenticatorVersion?): Boolean {
        return version?.isGreaterThenOrEqual(AuthenticatorVersion(4, 6, 0)) ?: false
    }
}
