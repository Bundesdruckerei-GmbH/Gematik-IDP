/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

//import de.bdr.servko.keycloak.gematik.idp.exception.ClientException
import de.bdr.servko.keycloak.gematik.idp.GematikIDP
import de.bdr.servko.keycloak.gematik.idp.exception.ClientException
import de.bdr.servko.keycloak.gematik.idp.exception.SessionNotFoundException
import de.bdr.servko.keycloak.gematik.idp.model.*
import de.bdr.servko.keycloak.gematik.idp.service.GematikIDPService
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpCertificateService
import de.bdr.servko.keycloak.gematik.idp.util.*
import jakarta.ws.rs.*
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriBuilder
import org.jboss.logging.Logger
import org.keycloak.OAuth2Constants
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider
import org.keycloak.common.util.Base64Url
import org.keycloak.common.util.SecretGenerator
import org.keycloak.common.util.Time
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.forms.login.freemarker.model.ClientBean
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.protocol.oidc.OIDCLoginProtocol
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
    abstract val initialFlowCardType: AuthenticationFlowType
    abstract val startingCardType: AuthenticationCardType

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
        @QueryParam(GematikIdpLiterals.ERROR_DESCRIPTION) errorDescription: String? = null,
        @QueryParam(GematikIdpLiterals.ERROR_URI) errorUri: String? = null,
        @HeaderParam(HttpHeaders.USER_AGENT) userAgent: String? = null,
    ): Response

    /**
     * Generates the Authenticator url.
     * redirectUri is our Keycloak instance /auth/realms/<realm>/broker/gematik-cidp/endpoint/result
     * challengePath is the central IDP
     */
    fun generateAuthenticatorUrl(
        encodedState: String,
        codeVerifier: String,
        flowType: AuthenticationFlowType,
        authenticatorPort: Int?,
        handShakeId: String?,
    ): URI {
        val challengePath =
            getChallengePath(encodedState, codeVerifier, flowType.typeName, authenticatorPort, handShakeId)
        return buildUri(handleAuthenticatorProtocol(), challengePath, null)
    }

    /**
     * Generate the Authorize url for the new flow.
     * redirectUri is our Keycloak instance /auth/realms/<realm>/broker/gematik-cidp/endpoint/result
     * challengePath is the central IDP
     */
    fun generateAuthorizeUrl(
        encodedState: String,
        codeVerifier: String,
        cardType: AuthenticationCardType,
        authenticatorPort: Int,
        handShakeId: String,
    ): URI {
        val baseUrl = "$LOCALHOST$authenticatorPort$AUTHORIZE_ENDPOINT"
        val challengePath = getChallengePath(encodedState, codeVerifier, cardType.typeName, null, null)
        return buildUri(UriBuilder.fromUri(baseUrl), challengePath, handShakeId)
    }

    fun buildUri(builder: UriBuilder, challengePath: URI, handShakeId: String? = null): URI {
        builder
            .queryParam(GematikIdpLiterals.CHALLENGE_PATH_PARAM, challengePath)
            .queryParam(GematikIdpLiterals.CALLBACK, GematikAuthenticatorCallbackType.DIRECT.simpleName())
            .apply {
                handShakeId?.let {
                    queryParam(GematikIdpLiterals.HANDSHAKE_ID, handShakeId)
                }
            }
        return builder.build()
    }

    private fun getChallengePath(
        encodedState: String,
        codeVerifier: String,
        cardType: String,
        authenticatorPort: Int?,
        handShakeId: String?,
    ): URI {
        val redirectUri = GematikIDPUtil.getEndpointUri(session, realm, null, config, GematikIdpLiterals.RESULT_PATH)
        return generateChallengePath(
            redirectUri, encodedState, codeVerifier, cardType, authenticatorPort, handShakeId
        )
    }

    private fun generateChallengePath(
        redirectUri: URI,
        encodedState: String,
        codeVerifier: String,
        cardType: String,
        authenticatorPort: Int?,
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
                queryParam(GematikIdpLiterals.SERVER_PORT_PARAMETER, authenticatorPort.toString())
            }
            handShakeId?.let {
                queryParam(GematikIdpLiterals.HANDSHAKE_ID, handShakeId)
            }
        }
        .build()

    /**
     * Generate status url for the new flow.
     */
    abstract fun probeAuthenticatorServerUrl(authenticatorPort: Int): URI

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
        withAuthSessionAndLoginTimeout(encodedState) { authSession ->
            val authenticatorPort = authSession.getAuthenticatorPortAuthNote()
            val handshakeId = authSession.getHandshakeIdAuthNote()
            val codeVerifier = authSession.getCodeVerifierAuthNote() ?: PkceUtils.generateCodeVerifier().also {
                authSession.setCodeVerifierAuthNote(it)
            }
            authSession.setGematikIDPStepAuthNote(initialStepName)
            generateAuthenticatorFormResponse(
                encodedState,
                codeVerifier,
                initialFlowCardType,
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
        @QueryParam(GematikIdpLiterals.AUTHENTICATOR_VERSION_PARAM) version: String?,
    ): Response {
        val authenticatorNextStepUrl = GematikIDPUtil.getEndpointUri(
            session, realm,
            GematikIDPState.fromEncodedState(encodedState), config,
            GematikIdpLiterals.AUTHENTICATOR_NEXT_STEP
        )
        return withAuthSessionAndLoginTimeout(
            encodedState,
            onSessionNotFound = { respondWithStatusRedirect(GematikIDPStep.ERROR.name, authenticatorNextStepUrl) })
        { authSession ->
            version?.let {
                authSession.setAuthenticatorVersionAuthNote(version)
            }
            val handshakeId = authSession.getHandshakeIdAuthNote()
            val authenticatorPort = authSession.getAuthenticatorPortAuthNote()
            val codeVerifier = authSession.getCodeVerifierAuthNote()
            if (authenticatorPort != null && handshakeId != null && codeVerifier != null) {
                val authorizeUrl =
                    generateAuthorizeUrl(encodedState, codeVerifier, startingCardType, authenticatorPort, handshakeId)
                Response.seeOther(authorizeUrl).build()
            } else {
                getMissingDataResponse()
            }
        }
    }

    /**
     * Called from gematik-idp.ftl after [de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig.getTimeoutMs]
     * milliseconds.
     */
    @GET
    @Path(GematikIdpLiterals.TIMEOUT_PATH)
    fun timeout(@QueryParam(OAuth2Constants.STATE) encodedState: String): Response {
        return withAuthSession(encodedState) { authSession ->
            forms.setAttribute("client", ClientBean(session, authSession.client))
                .createForm("gematik-idp-timeout.ftl")
        }
    }

    /**
     * The endpoint returns a JSON object containing the configured free‑port range.
     * The payload contains the expected `authenticatorPortRangeStart` and `authenticatorPortRangeEnd` values derived from the
     * configuration (`GematikIDPConfig`).
     */
    @GET
    @Path(GematikIdpLiterals.PREFLIGHT)
    @Produces(MediaType.APPLICATION_JSON)
    fun preflight(): Response {
        val portStart = config.getAuthenticatorPortRangeStart()
        val portEnd = config.getAuthenticatorPortRangeEnd()

        val dto = PreflightDto(
            authenticatorPortRangeStart = portStart,
            authenticatorPortRangeEnd = portEnd
        )
        return Response.ok(dto).build()
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
        } catch (ce: ClientException) {
            logger.error("Client not found or disabled during auth session resolution", ce)
            return handleInternalErrorWhenCalledFromBrowser(
                AuthenticatorErrorTypes.ERROR_IDP,
                ce.message,
                Response.Status.BAD_REQUEST
            )
        } catch (e: Exception) {
            logger.error("Failed to resolve auth session", e)
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build()
        }
        return block(authSession)
    }

    protected fun withAuthSessionAndLoginTimeout(
        encodedState: String,
        onSessionNotFound: ((SessionNotFoundException) -> Response)? = null,
        block: (AuthenticationSessionModel) -> Response,
    ): Response =
        withAuthSession(encodedState, onSessionNotFound) { authSession ->
            if (GematikIDPUtil.isLoginTimedOut(authSession, config.getLoginTimeoutMs())) {
                handleLoginTimeout()
            } else {
                block(authSession)
            }
        }

    /**
     * Generates the form response which is shown to a user at the beginning of each authentication step.
     */
    fun generateAuthenticatorFormResponse(
        encodedState: String,
        codeVerifier: String,
        flowType: AuthenticationFlowType,
        authenticatorPort: Int? = null,
        handshakeId: String? = null,
    ): Response {
        val disable417LoginFlow = "true".equals(
            realm.getAttribute(GematikIdpLiterals.DISABLE_4_17_LOGIN_FLOW_ATTRIBUTE),
            ignoreCase = true
        )

        val finalAuthenticatorPort = if (disable417LoginFlow) null else authenticatorPort
        val finalHandshakeId = if (disable417LoginFlow) null else handshakeId

        val authenticatorUrl =
            generateAuthenticatorUrl(encodedState, codeVerifier, flowType, finalAuthenticatorPort, finalHandshakeId)
        val brokerState = GematikIDPState.fromEncodedState(encodedState)
        val timeoutUrl =
            GematikIDPUtil.getEndpointUri(session, realm, brokerState, config, GematikIdpLiterals.TIMEOUT_PATH)
        val loginFormsProvider = forms
            .setAttribute("authenticatorUrl", authenticatorUrl)
            .setAttribute("timeoutUrl", timeoutUrl)
            .setAttribute("timeoutMs", config.getTimeoutMs())
            .setAttribute("authenticatorHttpServerTimeoutMs", config.getAuthenticatorHttpServerTimeoutMs())

        if (!disable417LoginFlow) {
            if (authenticatorPort != null && !handshakeId.isNullOrBlank()) {
                val authRequestUrl =
                    GematikIDPUtil.getEndpointUri(
                        session,
                        realm,
                        brokerState,
                        config,
                        GematikIdpLiterals.AUTH_REQUEST_PATH
                    )
                loginFormsProvider.setAttribute("authRequestUrl", authRequestUrl)
                loginFormsProvider.setAttribute(
                    "probeAuthenticatorServerUrl",
                    probeAuthenticatorServerUrl(authenticatorPort)
                )
            }
        }
        val statusUrl =
            GematikIDPUtil.getEndpointUri(session, realm, brokerState, config, GematikIdpLiterals.AUTHENTICATION_STATUS)

        loginFormsProvider.setAttribute("statusUrl", statusUrl)
        loginFormsProvider.setAttribute(GematikIDPConfig.AUTHENTICATOR_AUTO_LAUNCH, config.getAuthenticatorAutoLaunch())

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

    fun getMissingDataResponse() = handleInternalErrorWhenCalledFromBrowser(
        AuthenticatorErrorTypes.MISSING_DATA,
        "Missing data to start authentication.",
        Response.Status.BAD_REQUEST
    )

    fun getUnauthorizedResponse(cardType: AuthenticationCardType) = handleInternalErrorWhenCalledFromBrowser(
        AuthenticatorErrorTypes.UNAUTHORIZED,
        "ID token contains no claims – authentication failed for ${cardType.typeName}",
        Response.Status.UNAUTHORIZED
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

    fun handleSessionTimeout(e: SessionNotFoundException): Response =
        forms.setError(AuthenticatorErrorTypes.LOGIN_TIMEOUT.error, e.message)
            .createErrorPage(Response.Status.BAD_REQUEST)

    fun handleLoginTimeout(): Response =
        forms.setError(AuthenticatorErrorTypes.LOGIN_TIMEOUT.error, "Login timeout. Please log in again.")
            .createErrorPage(Response.Status.BAD_REQUEST)

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
