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

import de.bdr.servko.keycloak.gematik.idp.GematikIDP
import de.bdr.servko.keycloak.gematik.idp.exception.SessionNotFoundException
import de.bdr.servko.keycloak.gematik.idp.model.*
import de.bdr.servko.keycloak.gematik.idp.service.GematikIDPService
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpCertificateService
import de.bdr.servko.keycloak.gematik.idp.util.GematikIDPUtil
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriBuilder
import org.jboss.logging.Logger
import org.keycloak.OAuth2Constants
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.common.util.Time
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.forms.login.freemarker.model.ClientBean
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.protocol.oidc.utils.PkceUtils
import org.keycloak.sessions.AuthenticationSessionModel
import java.net.URI

abstract class GematikIDPResource {
    abstract val realm: RealmModel
    abstract val callback: IdentityProvider.AuthenticationCallback
    abstract val session: KeycloakSession
    abstract val gematikIDP: GematikIDP
    abstract val config: GematikIDPConfig
    abstract val service: GematikIDPService
    abstract val forms: LoginFormsProvider
    abstract val logger: Logger
    abstract val initialStepName: String
    abstract val initialCardType: String

    companion object {
        fun from(
            realm: RealmModel,
            callback: IdentityProvider.AuthenticationCallback,
            session: KeycloakSession,
            gematikIDP: GematikIDP,
            config: GematikIDPConfig,
            forms: LoginFormsProvider? = null,
        ): GematikIDPResource {
            val certificateService = GematikIdpCertificateService(
                realm = realm,
                session = session,
                config = config
            )
            val service = GematikIDPService(session)
            val loginFormsProvider = forms ?: session.getProvider(LoginFormsProvider::class.java)

            return when (config.getAuthenticationFlow()) {
                AuthenticationFlowType.MULTI -> {
                    GematikIDPMultiResource(
                        realm, callback, session, gematikIDP, config, service, loginFormsProvider, certificateService
                    )
                }

                AuthenticationFlowType.HBA -> {
                    GematikIDPHbaResource(
                        realm, callback, session, gematikIDP, config, service, loginFormsProvider, certificateService
                    )
                }

                AuthenticationFlowType.SMCB -> {
                    GematikIDPSmcbResource(
                        realm, callback, session, gematikIDP, config, service, loginFormsProvider, certificateService
                    )
                }

                else -> {
                    GematikIDPLegacyResource(
                        realm, callback, session, gematikIDP, config, service, loginFormsProvider, certificateService
                    )
                }
            }
        }

        //we have to escape spaces already, otherwise they are replaced with + symbol,
        //which is not handled by the Authenticator app
        fun escapeScope(scope: String) = scope.trim().replace(" ", "%20")
    }

    /**
     * Called by the browser to check the current status of the login process. Used as part of the new authentication
     * flows of the Gematik-Authenticator version 4.0 and above.
     */
    @GET
    @Path(GematikIdpLiterals.AUTHENTICATION_STATUS)
    abstract fun status(@QueryParam(OAuth2Constants.STATE) encodedState: String): Response

    /**
     * Wrapper for the next authenticator step to mitigate CORS error when redirecting to the Gematik-Authenticator
     * and to show error pages without directly redirecting in the status endpoint.
     */
    @GET
    @Path(GematikIdpLiterals.AUTHENTICATOR_NEXT_STEP)
    abstract fun nextStep(
        @QueryParam(OAuth2Constants.STATE) encodedState: String,
    ): Response

    /**
     * This endpoint handles the result produced by the Gematik-Authenticator.
     */
    @GET
    @Path(GematikIdpLiterals.RESULT_PATH)
    abstract fun result(
        code: String?,
        encodedState: String?,
        cardType: String? = null,
        error: String? = null,
        errorDetails: String? = null,
        errorUri: String? = null,
        userAgent: String? = null,
    ): Response

    /**
     * Generates the Authenticator url.
     * redirectUri is our Keycloak instance /auth/realms/<realm>/broker/gematik-cidp/endpoint/result
     * challengePath is the central IDP
     */
    abstract fun generateAuthenticatorUrl(encodedState: String, codeVerifier: String, cardType: String): URI

    /**
     * Initial call made by the user. We have access to the browser and therefore to the cookies.
     */
    @GET
    @Path(GematikIdpLiterals.START_AUTH_PATH)
    fun startAuth(@QueryParam(OAuth2Constants.STATE) encodedState: String): Response {
        val authSession: AuthenticationSessionModel = try {
            service.resolveAuthSessionFromEncodedState(realm, encodedState)
        } catch (snfe: SessionNotFoundException) {
            return handleSessionTimeout(snfe)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        val codeVerifier = PkceUtils.generateCodeVerifier()
        authSession.setAuthNote(GematikIdpLiterals.CODE_VERIFIER, codeVerifier)
        authSession.setAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP, initialStepName)

        return generateAuthenticatorFormResponse(encodedState, codeVerifier, initialCardType)
    }

    /**
     * Called from gematik-idp.ftl after [de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig.getTimeoutMs]
     * milliseconds.
     */
    @GET
    @Path(GematikIdpLiterals.TIMEOUT_PATH)
    fun timeout(@QueryParam(OAuth2Constants.STATE) encodedState: String): Response {
        val authSession: AuthenticationSessionModel = try {
            service.resolveAuthSessionFromEncodedState(realm, encodedState)
        } catch (snfe: SessionNotFoundException) {
            return handleSessionTimeout(snfe)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        return forms.setAttribute("client", ClientBean(session, authSession.client))
            .createForm("gematik-idp-timeout.ftl")
    }

    /**
     * Generates the form response which is shown to a user at the beginning of each authentication step.
     */
    fun generateAuthenticatorFormResponse(
        encodedState: String,
        codeVerifier: String,
        cardType: String,
    ): Response {
        val authenticatorUrl = generateAuthenticatorUrl(encodedState, codeVerifier, cardType)
        val brokerState = GematikIDPState.fromEncodedState(encodedState)
        val timeoutUrl =
            GematikIDPUtil.getEndpointUri(session, realm, brokerState, config, GematikIdpLiterals.TIMEOUT_PATH)

        val loginFormsProvider = forms.setAttribute("authenticatorUrl", authenticatorUrl)
            .setAttribute("timeoutUrl", timeoutUrl)
            .setAttribute("timeoutMs", config.getTimeoutMs())

        val statusUrl =
            GematikIDPUtil.getEndpointUri(session, realm, brokerState, config, GematikIdpLiterals.AUTHENTICATION_STATUS)

        loginFormsProvider.setAttribute("statusUrl", statusUrl)

        return loginFormsProvider.createForm("gematik-idp.ftl")
    }

    fun handleErrorWhenCalledFromBrowser(
        error: String?,
        errorDetails: String?,
        errorUri: String?,
    ): Response {
        logger.warn("Authenticator returned error: $error | error-details: $errorDetails | error-uri $errorUri")
        return forms.setError(AuthenticatorErrorTypes.valueOf(error).error, errorDetails ?: "Unknown")
            .createErrorPage(Response.Status.BAD_REQUEST)
    }

    fun getIncompleteIdpDataResponse() = handleInternalErrorWhenCalledFromBrowser(
        AuthenticatorErrorTypes.INCOMPLETE_IDP_DATA,
        "Tried to finalize login without complete authentication",
        Response.Status.BAD_REQUEST
    )

    fun handleInternalErrorWhenCalledFromBrowser(
        error: AuthenticatorErrorTypes?,
        errorDetails: String?,
        statusCode: Response.Status,
    ): Response {
        logger.error("Internal error while authenticating: $error | error-details: $errorDetails")
        return forms.setError(error?.error ?: AuthenticatorErrorTypes.ERROR_IDP.error, errorDetails ?: "Unknown")
            .createErrorPage(statusCode)
    }

    fun handleSessionTimeout(e: SessionNotFoundException): Response {
        return forms.setError(AuthenticatorErrorTypes.LOGIN_TIMEOUT.error, e.message)
            .createErrorPage(Response.Status.BAD_REQUEST)
    }

    fun handleAuthenticatorProtocol(): UriBuilder = UriBuilder.fromPath("//").scheme("authenticator")

    fun initIdentityContext(
        telematikId: String,
        authSession: AuthenticationSessionModel,
        hbaData: Map<String, Any>? = null,
        smcbData: Map<String, Any>? = null,
    ) = BrokeredIdentityContext(determineIdentityProviderID(telematikId), config).apply {
        authenticationSession = authSession
        idp = gematikIDP
        username = telematikId
        modelUsername = telematikId
        GematikIDPUtil.storeDataInContext(contextData = contextData, hbaData = hbaData, smcbData = smcbData)
    }

    fun respondWithStatusRedirect(currentStep: String, authenticatorNextStepUrl: URI): Response =
        Response.ok().entity(
            GematikIDPStatusResponse(
                currentStep, authenticatorNextStepUrl
            )
        ).build()

    private fun determineIdentityProviderID(telematikId: String): String {
        return if (config.getMultipleIdentityMode()) {
            "${telematikId}_${Time.currentTimeMillis()}"
        } else {
            telematikId
        }
    }

}
