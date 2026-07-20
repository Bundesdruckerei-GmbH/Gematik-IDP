/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.GematikIDP
import de.bdr.servko.keycloak.gematik.idp.exception.SessionNotFoundException
import de.bdr.servko.keycloak.gematik.idp.model.*
import de.bdr.servko.keycloak.gematik.idp.service.GematikIDPService
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpCertificateService
import de.bdr.servko.keycloak.gematik.idp.util.GematikIDPUtil
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals
import jakarta.ws.rs.*
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriBuilder
import org.jboss.logging.Logger
import org.keycloak.OAuth2Constants
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider
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
    abstract val callback: UserAuthenticationIdentityProvider.AuthenticationCallback
    abstract val session: KeycloakSession
    abstract val gematikIDP: GematikIDP
    abstract val config: GematikIDPConfig
    abstract val service: GematikIDPService
    abstract val forms: LoginFormsProvider
    abstract val logger: Logger
    abstract val initialStepName: String
    abstract val initialCardType: String
    abstract val startingCardType: String

    companion object {
        fun from(
            realm: RealmModel,
            callback: UserAuthenticationIdentityProvider.AuthenticationCallback,
            session: KeycloakSession,
            gematikIDP: GematikIDP,
            config: GematikIDPConfig,
            forms: LoginFormsProvider? = null,
        ): GematikIDPResource {
            val certificateService = GematikIdpCertificateService(
                realm = realm,
                session = session,
                config = config,
            )
            val service = GematikIDPService(session)
            val loginFormsProvider = forms ?: session.getProvider(LoginFormsProvider::class.java)

            return when (config.getAuthenticationFlow()) {
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
                    GematikIDPMultiResource(
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
        @QueryParam(OAuth2Constants.CODE) code: String?,
        @QueryParam(OAuth2Constants.STATE) encodedState: String?,
        @QueryParam(GematikIdpLiterals.CARD_TYPE) cardType: String? = null,
        @QueryParam(GematikIdpLiterals.ERROR) error: String? = null,
        @QueryParam(GematikIdpLiterals.ERROR_DETAILS) errorDetails: String? = null,
        @QueryParam(GematikIdpLiterals.ERROR_URI) errorUri: String? = null,
        @HeaderParam(HttpHeaders.USER_AGENT) userAgent: String? = null,
    ): Response

    /**
     * Generates the Authenticator url.
     * redirectUri is our Keycloak instance /auth/realms/<realm>/broker/gematik-cidp/endpoint/result
     * challengePath is the central IDP
     */
    abstract fun generateAuthenticatorUrl(
        encodedState: String,
        codeVerifier: String,
        cardType: String,
        authenticatorPort: String?,
        handShakeId: String?,
    ): URI

    /**
     * Generate the Authorize url for the new flow.
     * redirectUri is our Keycloak instance /auth/realms/<realm>/broker/gematik-cidp/endpoint/result
     * challengePath is the central IDP
     */
    abstract fun generateAuthorizeUrl(
        encodedState: String,
        codeVerifier: String,
        cardType: String,
        authenticatorPort: String,
        handShakeId: String,
    ): URI

    /**
     * Generate status url for the new flow.
     */
    abstract fun probeAuthenticatorServerUrl(authenticatorPort: String): URI

    /**
     * Initial call made by the user. We have access to the browser and therefore to the cookies.
     * The startAuth endpoint initializes the authentication session and renders the
     * HTML form (gematik-idp.ftl). It now optionally accepts a `freePort` query
     * parameter that is discovered on the client side. When present the value is
     * propagated to the template so that the front‑end can include it in the
     * configuration JSON.
     */
    @GET
    @Path(GematikIdpLiterals.START_AUTH_PATH)
    fun startAuth(
        @QueryParam(OAuth2Constants.STATE) encodedState: String,
    ): Response =
        withAuthSession(encodedState) { authSession ->
            val authenticatorPort = authSession.getAuthNote(GematikIdpLiterals.AUTHENTICATOR_PORT)
                ?: return@withAuthSession Response.status(Response.Status.BAD_REQUEST)
                    .entity("Missing authenticatorPort")
                    .build()
            val handshakeId = authSession.getAuthNote(GematikIdpLiterals.HANDSHAKE_ID)
            val codeVerifier = PkceUtils.generateCodeVerifier()
            authSession.setAuthNote(GematikIdpLiterals.CODE_VERIFIER, codeVerifier)
            authSession.setAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP, initialStepName)
            generateAuthenticatorFormResponse(
                encodedState,
                codeVerifier,
                initialCardType,
                authenticatorPort,
                handshakeId
            )
        }

    /**
     * The authRequest endpoint creates the url for the authorize endpoint.
     */
    @GET
    @Path(GematikIdpLiterals.AUTH_REQUEST_PATH)
    fun authRequest(
        @QueryParam(OAuth2Constants.STATE) encodedState: String,
        @QueryParam(GematikIdpLiterals.AUTHENTICATOR_VERSION_PARAM) version: String,
    ): Response {
        val authenticatorNextStepUrl = GematikIDPUtil.getEndpointUri(
            session, realm,
            GematikIDPState.fromEncodedState(encodedState), config,
            GematikIdpLiterals.AUTHENTICATOR_NEXT_STEP
        )
        return withAuthSession(
            encodedState,
            onSessionNotFound = { respondWithStatusRedirect(GematikIDPStep.ERROR.name, authenticatorNextStepUrl) })
        { authSession ->
            authSession.setAuthNote(GematikIdpLiterals.AUTHENTICATOR_VERSION, version)
            val handshakeId = authSession.getAuthNote(GematikIdpLiterals.HANDSHAKE_ID)
            val authenticatorPort = authSession.getAuthNote(GematikIdpLiterals.AUTHENTICATOR_PORT)
            val codeVerifier = authSession.getAuthNote(GematikIdpLiterals.CODE_VERIFIER)
            val authorizeUrl =
                generateAuthorizeUrl(encodedState, codeVerifier, startingCardType, authenticatorPort, handshakeId)
            Response.seeOther(authorizeUrl).build()
        }
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
            return callback.error(config, "Failed to resolve auth session: ${e.message}")
        }

        return forms.setAttribute("client", ClientBean(session, authSession.client))
            .createForm("gematik-idp-timeout.ftl")
    }

    /**
     * The endpoint returns a JSON object containing the configured free‑port range.
     * The payload contains the expected `portRangeStart` and `portRangeEnd` values derived from the
     * configuration (`GematikIDPConfig`).
     */
    @GET
    @Path(GematikIdpLiterals.PREFLIGHT)
    @Produces(MediaType.APPLICATION_JSON)
    fun preflight(): Response {
        val portStart = config.getAuthenticatorPortRangeStart()
        val portEnd = config.getAuthenticatorPortRangeEnd()

        return Response.ok(
            mapOf(
                "authenticatorPortRangeStart" to portStart,
                "authenticatorPortRangeEnd" to portEnd,
            )
        ).build()
    }

    protected fun withAuthSession(
        encodedState: String,
        onSessionNotFound: ((SessionNotFoundException) -> Response)? = null,
        block: (AuthenticationSessionModel) -> Response,
    ): Response {
        val authSession = try {
            service.resolveAuthSessionFromEncodedState(realm, encodedState)
        } catch (snfe: SessionNotFoundException) {
            return onSessionNotFound?.invoke(snfe) ?: handleSessionTimeout(snfe)
        } catch (e: Exception) {
            return callback.error(config, "Failed to resolve auth session: ${e.message}")
        }

        if (GematikIDPUtil.isLoginTimedOut(authSession, config.getLoginTimeoutMs())) {
            return handleLoginTimeout()
        }

        return block(authSession)
    }

    /**
     * Generates the form response which is shown to a user at the beginning of each authentication step.
     */
    fun generateAuthenticatorFormResponse(
        encodedState: String,
        codeVerifier: String,
        cardType: String,
        authenticatorPort: String? = null,
        handshakeId: String? = null,
    ): Response {
        val authenticatorUrl =
            generateAuthenticatorUrl(encodedState, codeVerifier, cardType, authenticatorPort, handshakeId)
        val brokerState = GematikIDPState.fromEncodedState(encodedState)
        val timeoutUrl =
            GematikIDPUtil.getEndpointUri(session, realm, brokerState, config, GematikIdpLiterals.TIMEOUT_PATH)
        val loginFormsProvider = forms
            .setAttribute("authenticatorUrl", authenticatorUrl)
            .setAttribute("timeoutUrl", timeoutUrl)
            .setAttribute("timeoutMs", config.getTimeoutMs())
            .setAttribute("authenticatorHttpServerTimeoutMs", config.getAuthenticatorHttpServerTimeoutMs())

        if (!authenticatorPort.isNullOrBlank() && !handshakeId.isNullOrBlank()) {
            val authRequestUrl =
                GematikIDPUtil.getEndpointUri(session, realm, brokerState, config, GematikIdpLiterals.AUTH_REQUEST_PATH)
            loginFormsProvider.setAttribute("authRequestUrl", authRequestUrl)
            loginFormsProvider.setAttribute(
                "probeAuthenticatorServerUrl",
                probeAuthenticatorServerUrl(authenticatorPort)
            )
        }
        val statusUrl =
            GematikIDPUtil.getEndpointUri(session, realm, brokerState, config, GematikIdpLiterals.AUTHENTICATION_STATUS)

        loginFormsProvider.setAttribute("statusUrl", statusUrl)
        loginFormsProvider.setAttribute(GematikIDPConfig.AUTHENTICATOR_AUTO_LAUNCH, config.getAuthenticatorAutoLaunch())
        loginFormsProvider.setAttribute("authenticatorPortRangeStart", config.getAuthenticatorPortRangeStart())
        loginFormsProvider.setAttribute("authenticatorPortRangeEnd", config.getAuthenticatorPortRangeEnd())

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

    fun handleLoginTimeout(): Response {
        return forms.setError(AuthenticatorErrorTypes.LOGIN_TIMEOUT.error, "Login timeout. Please log in again.")
            .createErrorPage(Response.Status.BAD_REQUEST)
    }

    fun handleAuthenticatorProtocol(): UriBuilder = UriBuilder.fromPath("//").scheme("authenticator")

    fun handleAuthorizeEndpoint(baseUrl: String): UriBuilder = UriBuilder.fromUri(baseUrl)

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
