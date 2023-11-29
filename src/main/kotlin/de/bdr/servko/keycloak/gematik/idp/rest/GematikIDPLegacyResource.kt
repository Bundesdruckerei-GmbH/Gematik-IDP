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
 *
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.GematikIDP
import de.bdr.servko.keycloak.gematik.idp.model.*
import de.bdr.servko.keycloak.gematik.idp.service.GematikIDPService
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpCertificateService
import de.bdr.servko.keycloak.gematik.idp.util.ErrorUtils
import de.bdr.servko.keycloak.gematik.idp.util.GematikIDPUtil
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals
import de.bdr.servko.keycloak.gematik.idp.util.VersionFromUserAgentReader
import jakarta.ws.rs.*
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriBuilder
import org.jboss.logging.Logger
import org.jose4j.jwt.consumer.JwtContext
import org.keycloak.OAuth2Constants
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.common.util.Base64Url
import org.keycloak.common.util.SecretGenerator
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.protocol.oidc.utils.PkceUtils
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.util.JsonSerialization
import java.net.URI

class GematikIDPLegacyResource(
    override val realm: RealmModel,
    override val callback: IdentityProvider.AuthenticationCallback,
    override val session: KeycloakSession,
    override val gematikIDP: GematikIDP,
    override val config: GematikIDPConfig,
    override val service: GematikIDPService,
    override val forms: LoginFormsProvider = session.getProvider(LoginFormsProvider::class.java),
    private val certificateService: GematikIdpCertificateService,
    override val initialStepName: String = GematikIDPStep.REQUESTED_HBA_DATA.name,
    override val initialCardType: String = GematikIdpLiterals.SCOPE_HBA,
) : GematikIDPResource() {
    override val logger: Logger = Logger.getLogger(this::class.java)

    /**
     * Called by the browser to check the current status of the login process. Used as part of the new authentication
     * flow of the Gematik-Authenticator version 4.0 and above.
     * Returns 202, while Authenticator is processing.
     * Returns 200, after successful Authenticator call.
     */
    @GET
    @Path(GematikIdpLiterals.AUTHENTICATION_STATUS)
    override fun status(@QueryParam(OAuth2Constants.STATE) encodedState: String): Response {
        val authSession: AuthenticationSessionModel = try {
            service.resolveAuthSessionFromEncodedState(realm, encodedState)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        val hbaData = authSession.getAuthNote(GematikIdpLiterals.HBA_DATA)
        val smcbData = authSession.getAuthNote(GematikIdpLiterals.SMCB_DATA)
        val step = GematikIDPUtil.getGematikIdpStepFrom(authSession)

        if ((step == GematikIDPStep.REQUESTED_HBA_DATA && hbaData == null) ||
            (step == GematikIDPStep.REQUESTED_SMCB_DATA && smcbData == null)
        ) {
            return Response.status(Response.Status.ACCEPTED)
                .entity(GematikIDPStatusResponse(step.name, null))
                .build()
        }

        if ((step == GematikIDPStep.RECEIVED_HBA_DATA && hbaData.isNotEmpty()) ||
            (step == GematikIDPStep.RECEIVED_SMCB_DATA && smcbData.isNotEmpty()) ||
            (step == GematikIDPStep.ERROR)
        ) {
            val authenticatorNextStepUrl = GematikIDPUtil.getEndpointUri(
                session,
                realm,
                GematikIDPState.fromEncodedState(encodedState),
                config,
                GematikIdpLiterals.AUTHENTICATOR_NEXT_STEP
            )
            return Response.ok()
                .entity(GematikIDPStatusResponse(step.name, URI(authenticatorNextStepUrl.toString())))
                .build()
        }

        return callback.error("Invalid state. Please restart authentication flow.")
    }

    /**
     * Wrapper for the next authenticator step to mitigate CORS error when redirecting to the Gematik-Authenticator
     * and to show error pages without directly redirecting in the status endpoint.
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

        val step = GematikIDPUtil.getGematikIdpStepFrom(authSession)
        val codeVerifier = authSession.getAuthNote(GematikIdpLiterals.CODE_VERIFIER)

        return when (step) {
            GematikIDPStep.RECEIVED_HBA_DATA -> {
                handleHBAData(encodedState, codeVerifier, authSession)
            }

            GematikIDPStep.ERROR -> {
                val error = authSession.getAuthNote(GematikIdpLiterals.ERROR)
                val errorDetails = authSession.getAuthNote(GematikIdpLiterals.ERROR_DETAILS)
                val errorUri = authSession.getAuthNote(GematikIdpLiterals.ERROR_URI)

                handleIdpErrorWhenCalledFromBrowser(error, errorDetails, errorUri)
            }

            else -> {
                val smcbData = GematikIDPUtil.getCertificateDataFromAuthNote(authSession, GematikIdpLiterals.SMCB_DATA)
                    ?: return getIncompleteIdpDataResponse()

                handleSMCBData(authSession, smcbData)
            }
        }
    }

    /**
     * This is called from the authenticator app. Since we have no session cookie in the authenticator app,
     * forward to the user's browser, where we have access to the initial session.
     * Authenticator app is forwarding for 302
     */
    @POST
    @Path(GematikIdpLiterals.RESULT_PATH)
    fun resultPost(): Response = Response.status(Response.Status.FOUND).build()

    /**
     * This is either called in the old authentication flow from the browser or in the new authentication flow by the
     * Gematik-Authenticator.
     * In the browser, we have access to the cookies and can therefore use them to resolve the
     * authentication session.
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
            return handleIdpErrorWhenCalledFromBrowser(error, errorDetails, errorUri)
        }

        val authSession: AuthenticationSessionModel = try {
            service.resolveAuthSessionFromEncodedState(realm, encodedState!!)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        GematikIDPUtil.setAuthenticatorVersionInAuthSession(version, authSession)

        if (error != null || errorDetails != null || errorUri != null) {
            return ErrorUtils.saveIdpErrorInAuthSession(authSession, error, errorDetails, errorUri)
        }

        val codeVerifier = authSession.getAuthNote(GematikIdpLiterals.CODE_VERIFIER)
        val idToken = certificateService.fetchIdToken(codeVerifier, code!!)
        var step = gematikIDPStepSanityCheck(idToken, GematikIDPUtil.getGematikIdpStepFrom(authSession), authSession)

        val claimsMap = idToken.jwtClaims.claimsMap
        when (step) {
            GematikIDPStep.REQUESTED_HBA_DATA -> {
                logger.debug("HBA-DATA: ${claimsMap.map { (k, v) -> "$k:$v\n" }}")
                step = GematikIDPStep.RECEIVED_HBA_DATA
                authSession.setAuthNote(GematikIdpLiterals.HBA_DATA, JsonSerialization.writeValueAsString(claimsMap))
                authSession.setAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP, step.name)
            }

            GematikIDPStep.REQUESTED_SMCB_DATA -> {
                logger.debug("SMCB-DATA: ${claimsMap.map { (k, v) -> "$k:$v\n" }}")
                step = GematikIDPStep.RECEIVED_SMCB_DATA
                authSession.setAuthNote(GematikIdpLiterals.SMCB_DATA, JsonSerialization.writeValueAsString(claimsMap))
                authSession.setAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP, step.name)
            }

            else -> {
                callback.error("invalid step $step")
            }
        }

        return Response.ok().type(MediaType.APPLICATION_JSON_TYPE).build()
    }

    private fun handleSMCBData(
        authSession: AuthenticationSessionModel,
        claims: Map<String, Any>,
    ): Response {
        val hbaData = GematikIDPUtil.getCertificateDataFromAuthNote(authSession, GematikIdpLiterals.HBA_DATA)
            ?: return getIncompleteIdpDataResponse()

        val telematikId = hbaData[ContextData.CONTEXT_HBA_TELEMATIK_ID.claim.value] as String

        return callback.authenticated(
            initIdentityContext(
                telematikId = telematikId,
                authSession = authSession,
                hbaData = hbaData,
                smcbData = claims
            )
        )
    }

    private fun handleHBAData(
        encodedState: String,
        codeVerifier: String,
        authSession: AuthenticationSessionModel,
    ): Response {
        authSession.setAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP, GematikIDPStep.REQUESTED_SMCB_DATA.name)
        return generateAuthenticatorFormResponse(encodedState, codeVerifier, GematikIdpLiterals.SCOPE_SMCB)
    }

    /**
     * Generate the Authenticator url.
     * redirectUri is our Keycloak instance /auth/realms/<realm>/broker/gematik-cidp/endpoint/result
     * challengePath is the central IDP
     */
    override fun generateAuthenticatorUrl(encodedState: String, codeVerifier: String, cardType: String): URI {
        val redirectUri = GematikIDPUtil.getEndpointUri(
            session,
            realm,
            null,
            config,
            GematikIdpLiterals.RESULT_PATH
        )
        val challengePath = generateChallengePath(
            redirectUri,
            encodedState,
            codeVerifier,
            cardType
        )
        val uriBuilder = handleAuthenticatorProtocol()
            .queryParam(GematikIdpLiterals.CHALLENGE_PATH, challengePath)

        uriBuilder.queryParam(GematikIdpLiterals.CALLBACK, GematikAuthenticatorCallbackType.DIRECT.simpleName())

        return uriBuilder
            .build()
    }

    private fun generateChallengePath(
        redirectUri: URI,
        encodedState: String,
        codeVerifier: String,
        additionalScope: String,
    ): URI = UriBuilder.fromUri(config.getAuthenticatorAuthorizationUrl())
        .queryParam(OAuth2Constants.CLIENT_ID, config.clientId)
        .queryParam(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.CODE)
        .queryParam(OAuth2Constants.REDIRECT_URI, redirectUri)
        .queryParam(OAuth2Constants.STATE, encodedState)
        .queryParam(
            OAuth2Constants.SCOPE,
            escapeScope("${config.defaultScope.trim()} $additionalScope")
        )
        .queryParam(OAuth2Constants.CODE_CHALLENGE, PkceUtils.generateS256CodeChallenge(codeVerifier))
        .queryParam(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)
        .queryParam(OIDCLoginProtocol.NONCE_PARAM, Base64Url.encode(SecretGenerator.getInstance().randomBytes(16)))
        .build()


    /**
     * When calling this plugin in a browser based on Chromium, the second opening tab may not open the
     * Gematik-Authenticator. See https://partner.bdr.de/jira/browse/SERVKO-1413
     * When reloading this new tab, the HBA-data is written in the SMCB-fields, because the IDP step auth notes gets
     * scrambled. To mitigate this, we make a sanity check, if the ID-token contains an organization name, when the
     * step is RECEIVED_HBA_DATA, because the HBA hasn't got this field.
     *
     * @param idToken
     * @param step
     * @param authSession
     * @return
     */
    fun gematikIDPStepSanityCheck(
        idToken: JwtContext,
        step: GematikIDPStep,
        authSession: AuthenticationSessionModel,
    ): GematikIDPStep {
        if (!idToken.jwtClaims.hasClaim("organizationName") && step == GematikIDPStep.RECEIVED_HBA_DATA) {
            val nextStep = GematikIDPStep.REQUESTED_HBA_DATA
            authSession.setAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP, nextStep.name)
            return nextStep
        }
        return step
    }
}
