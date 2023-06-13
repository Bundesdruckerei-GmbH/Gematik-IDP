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

package de.bdr.servko.keycloak.gematik.idp

import de.bdr.servko.keycloak.gematik.idp.extension.BrainpoolCurves
import de.bdr.servko.keycloak.gematik.idp.model.*
import org.jboss.logging.Logger
import org.jose4j.json.internal.json_simple.parser.JSONParser
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers
import org.jose4j.jwk.PublicJsonWebKey
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.jwt.consumer.JwtContext
import org.keycloak.OAuth2Constants
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.common.util.Base64Url
import org.keycloak.common.util.SecretGenerator
import org.keycloak.common.util.Time
import org.keycloak.crypto.Algorithm
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.forms.login.freemarker.model.ClientBean
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.protocol.oidc.utils.PkceUtils
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.util.JsonSerialization
import java.net.URI
import javax.crypto.spec.SecretKeySpec
import javax.ws.rs.*
import javax.ws.rs.core.MediaType
import javax.ws.rs.core.Response
import javax.ws.rs.core.UriBuilder

open class GematikIDPEndpoint(
    private val realm: RealmModel,
    private val callback: IdentityProvider.AuthenticationCallback,
    private val session: KeycloakSession,
    private val gematikIDP: GematikIDP,
    private val config: GematikIDPConfig,
    private val forms: LoginFormsProvider = session.getProvider(LoginFormsProvider::class.java),
    private val service: GematikIDPService = GematikIDPService(session),
) {
    companion object {
        const val START_AUTH_PATH = "startAuth"
        const val RESULT_PATH = "result"
        const val AUTHENTICATION_STATUS = "authenticationStatus"
        const val AUTHENTICATOR_NEXT_STEP = "authenticatorNextStep"

        const val CHALLENGE_PATH = "challenge_path"
        const val CALLBACK = "callback"

        const val SCOPE_HBA = "Person_ID"
        const val SCOPE_SMCB = "Institutions_ID"
        const val TOKEN_KEY = "token_key"
        const val KEY_VERIFIER = "key_verifier"

        const val CODE_VERIFIER = "CODE_VERIFIER"
        const val GEMATIK_IDP_STEP = "GEMATIK_IDP_STEP"
        const val HBA_DATA = "HBA_DATA"
        const val SMCB_DATA = "SMCB_DATA"

        const val ERROR = "error"
        const val ERROR_DETAILS = "error_details"
        const val ERROR_URI = "error_uri"
    }

    enum class GematikIDPStep {
        REQUESTED_HBA_DATA,
        RECEIVED_HBA_DATA,
        REQUESTED_SMCB_DATA,
        RECEIVED_SMCB_DATA,
        IDP_ERROR
    }

    enum class GematikAuthenticatorCallbackType {
        OPEN_TAB,
        DIRECT,
        DEEPLINK;

        fun simpleName() = this.name.lowercase()
    }

    private val logger: Logger = Logger.getLogger(this::class.java)

    /**
     * Initial call made by the user. We have access to the browser and therefore to the cookies.
     */
    @GET
    @Path(START_AUTH_PATH)
    fun startAuth(@QueryParam(OAuth2Constants.STATE) encodedState: String): Response {
        val authSession: AuthenticationSessionModel = try {
            service.resolveAuthSessionFromEncodedState(realm, encodedState)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        val codeVerifier = PkceUtils.generateCodeVerifier()
        authSession.setAuthNote(CODE_VERIFIER, codeVerifier)
        var disableHbaAuthentication = config.getDisableHbaAuthentication()
        var nextStep = if (disableHbaAuthentication) GematikIDPStep.REQUESTED_SMCB_DATA.name else GematikIDPStep.REQUESTED_HBA_DATA.name;
        var scope = if (disableHbaAuthentication) SCOPE_SMCB else SCOPE_HBA
        authSession.setAuthNote(GEMATIK_IDP_STEP, nextStep)

        return generateAuthenticatorFormResponse(encodedState, codeVerifier, scope)
    }

    /**
     * Called from gematik-idp.ftl after [de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig.getTimeoutMs]
     * milliseconds.
     */
    @GET
    @Path("timeout")
    fun timeout(@QueryParam(OAuth2Constants.STATE) encodedState: String): Response {
        val authSession: AuthenticationSessionModel = try {
            service.resolveAuthSessionFromEncodedState(realm, encodedState)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        return forms.setAttribute("client", ClientBean(session, authSession.client))
            .createForm("gematik-idp-timeout.ftl")
    }

    /**
     * Called by the browser to check the current status of the login process. Used as part of the new authentication
     * flow of the Gematik-Authenticator version 4.0 and above.
     * Returns 202, while Authenticator is processing.
     * Returns 200, after successful Authenticator call.
     */
    @GET
    @Path(AUTHENTICATION_STATUS)
    fun status(@QueryParam(OAuth2Constants.STATE) encodedState: String): Response {
        val authSession: AuthenticationSessionModel = try {
            service.resolveAuthSessionFromEncodedState(realm, encodedState)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        val hbaData = authSession.getAuthNote(HBA_DATA)
        val smcbData = authSession.getAuthNote(SMCB_DATA)
        val step = getGematikIdpStepFrom(authSession)

        if ((step == GematikIDPStep.REQUESTED_HBA_DATA && hbaData == null) ||
            (step == GematikIDPStep.REQUESTED_SMCB_DATA && smcbData == null)
        ) {
            return Response.status(Response.Status.ACCEPTED)
                .entity(GematikIDPStatusResponse(step.name, null))
                .build()
        }

        if ((step == GematikIDPStep.RECEIVED_HBA_DATA && hbaData.isNotEmpty()) ||
            (step == GematikIDPStep.RECEIVED_SMCB_DATA && smcbData.isNotEmpty()) ||
            (step == GematikIDPStep.IDP_ERROR)
        ) {
            val authenticatorNextStepUrl = gematikIDP.getEndpointUri(
                session,
                realm,
                GematikIDPState.fromEncodedState(encodedState),
                config,
                AUTHENTICATOR_NEXT_STEP
            )
            return Response.ok()
                .entity(GematikIDPStatusResponse(step.name, URI(authenticatorNextStepUrl.toString())))
                .build()
        }

        return callback.error("Invalid state. Please restart authentication flow.")
    }

    /**
     * Wrapper for the next authenticator step to mitigate CORS error when redirecting to the Gematik-Authenticator
     */
    @GET
    @Path(AUTHENTICATOR_NEXT_STEP)
    fun authenticatorNextStep(
        @QueryParam(OAuth2Constants.STATE) encodedState: String,
    ): Response {
        val authSession: AuthenticationSessionModel = try {
            service.resolveAuthSessionFromEncodedState(realm, encodedState)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        val step = getGematikIdpStepFrom(authSession)
        val codeVerifier = authSession.getAuthNote(CODE_VERIFIER)

        return when (step) {
            GematikIDPStep.RECEIVED_HBA_DATA -> {
                handleHBAData(encodedState, codeVerifier, authSession)
            }

            GematikIDPStep.IDP_ERROR -> {
                val error = authSession.getAuthNote(ERROR)
                val errorDetails = authSession.getAuthNote(ERROR_DETAILS)
                val errorUri = authSession.getAuthNote(ERROR_URI)

                handleIdpErrorWhenCalledFromBrowser(error, errorDetails, errorUri)
            }

            else -> {
                val smcbData = getCertificateDataFromAuthNote(authSession, SMCB_DATA)
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
    @Path(RESULT_PATH)
    fun resultPost(): Response = Response.status(Response.Status.FOUND).build()

    /**
     * We are in the browser again, so we have access to the auth session and therefore to the code_verifier.
     */
    @GET
    @Path(RESULT_PATH)
    fun result(
        @QueryParam(OAuth2Constants.CODE) code: String?,
        @QueryParam(OAuth2Constants.STATE) encodedState: String?,
        @QueryParam(ERROR) error: String? = null,
        @QueryParam(ERROR_DETAILS) errorDetails: String? = null,
        @QueryParam(ERROR_URI) errorUri: String? = null,
    ): Response {
        if (code == null && encodedState == null) {
            return handleIdpErrorWhenCalledFromBrowser(error, errorDetails, errorUri)
        }

        val authSession: AuthenticationSessionModel = try {
            service.resolveAuthSessionFromEncodedState(realm, encodedState!!)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        if (error != null || errorDetails != null || errorUri != null) {
            return saveIdpErrorInAuthSession(authSession, error, errorDetails, errorUri)
        }

        val codeVerifier = authSession.getAuthNote(CODE_VERIFIER)
        val idToken = fetchIdToken(codeVerifier, code!!)
        var step = getGematikIdpStepFrom(authSession).let {
            gematikIDPStepSanityCheck(idToken, it, authSession)
        }

        val claimsMap = idToken.jwtClaims.claimsMap
        when (step) {
            GematikIDPStep.REQUESTED_HBA_DATA -> {
                logger.debug("HBA-DATA: ${claimsMap.map { (k, v) -> "$k:$v\n" }}")
                step = GematikIDPStep.RECEIVED_HBA_DATA
                authSession.setAuthNote(HBA_DATA, JsonSerialization.writeValueAsString(claimsMap))
                authSession.setAuthNote(GEMATIK_IDP_STEP, step.name)
            }

            GematikIDPStep.REQUESTED_SMCB_DATA -> {
                logger.debug("SMCB-DATA: ${claimsMap.map { (k, v) -> "$k:$v\n" }}")
                step = GematikIDPStep.RECEIVED_SMCB_DATA
                authSession.setAuthNote(SMCB_DATA, JsonSerialization.writeValueAsString(claimsMap))
                authSession.setAuthNote(GEMATIK_IDP_STEP, step.name)
            }

            else -> {
                callback.error("invalid step $step")
            }
        }

        if (!config.getNewAuthenticationFlow()) {
            return resultLegacy(encodedState, codeVerifier, step, claimsMap, authSession)
        }

        return Response.ok().type(MediaType.APPLICATION_JSON_TYPE).build()
    }

    private fun saveIdpErrorInAuthSession(
        authSession: AuthenticationSessionModel,
        error: String?,
        errorDetails: String?,
        errorUri: String?,
    ): Response {
        authSession.setAuthNote(ERROR, error)
        authSession.setAuthNote(ERROR_DETAILS, errorDetails)
        authSession.setAuthNote(ERROR_URI, errorUri)
        authSession.setAuthNote(GEMATIK_IDP_STEP, GematikIDPStep.IDP_ERROR.name)

        return Response.noContent().build()
    }

    private fun handleIdpErrorWhenCalledFromBrowser(
        error: String?,
        errorDetails: String?,
        errorUri: String?
    ): Response {
        logger.error("Authenticator returned error: $error | error-details: $errorDetails | error-uri $errorUri")
        return forms.setError("authenticator.errorIdp", errorDetails?.take(20) ?: "Unknown")
            .createErrorPage(Response.Status.BAD_REQUEST)
    }

    private fun getGematikIdpStepFrom(authSession: AuthenticationSessionModel): GematikIDPStep {
        return authSession.getAuthNote(GEMATIK_IDP_STEP).let {
            GematikIDPStep.valueOf(it)
        }
    }

    private fun generateAuthenticatorFormResponse(
        encodedState: String,
        codeVerifier: String,
        scope: String,
    ): Response {
        val authenticatorUrl = generateAuthenticatorUrl(encodedState, codeVerifier, scope)
        val brokerState = GematikIDPState.fromEncodedState(encodedState)
        val timeoutUrl =
            gematikIDP.getEndpointUri(session, realm, brokerState, config, "timeout")

        val loginFormsProvider = forms.setAttribute("authenticatorUrl", authenticatorUrl)
            .setAttribute("timeoutUrl", timeoutUrl)
            .setAttribute("timeoutMs", config.getTimeoutMs())

        if (config.getNewAuthenticationFlow()) {
            val statusUrl =
                gematikIDP.getEndpointUri(session, realm, brokerState, config, "status")

            loginFormsProvider.setAttribute("statusUrl", statusUrl)
        }

        return loginFormsProvider.createForm("gematik-idp.ftl")
    }

    /**
     * Legacy functionality of the legacy authentication flow
     */
    private fun resultLegacy(
        encodedState: String,
        codeVerifier: String,
        step: GematikIDPStep,
        claims: Map<String, Any>,
        authSession: AuthenticationSessionModel,
    ): Response {
        return when (step) {
            GematikIDPStep.RECEIVED_HBA_DATA -> {
                return handleHBAData(encodedState, codeVerifier, authSession)
            }

            GematikIDPStep.RECEIVED_SMCB_DATA -> {
                return handleSMCBData(authSession, claims)
            }

            else -> {
                callback.error("invalid step $step")
            }
        }
    }

    private fun handleSMCBData(
        authSession: AuthenticationSessionModel,
        claims: Map<String, Any>,
    ): Response {
        val smcbData = claims
        var telematikId = smcbData[ContextData.CONTEXT_SMCB_TELEMATIK_ID.claim.value] as String

        var hbaData = emptyMap<String, Any>()
        if (!config.getDisableHbaAuthentication()) {
            hbaData = getCertificateDataFromAuthNote(authSession, HBA_DATA)
            telematikId = hbaData[ContextData.CONTEXT_HBA_TELEMATIK_ID.claim.value] as String
        }

        val identityContext =
            BrokeredIdentityContext(determineIdentityProviderID(telematikId))
                .apply {
                    authenticationSession = authSession
                    idp = gematikIDP
                    idpConfig = config
                    username = telematikId
                    modelUsername = telematikId
                    storeDataInContext(contextData, hbaData, smcbData)
                }

        return callback.authenticated(identityContext)
    }

    private fun getCertificateDataFromAuthNote(
        authSession: AuthenticationSessionModel,
        authNote: String,
    ): Map<String, Any> {
        //we set HBA_DATA as claims map, so we know the types
        @Suppress("UNCHECKED_CAST")
        return JsonSerialization.readValue(authSession.getAuthNote(authNote), Map::class.java) as Map<String, Any>
    }

    private fun handleHBAData(
        encodedState: String,
        codeVerifier: String,
        authSession: AuthenticationSessionModel,
    ): Response {
        authSession.setAuthNote(GEMATIK_IDP_STEP, GematikIDPStep.REQUESTED_SMCB_DATA.name)
        return generateAuthenticatorFormResponse(encodedState, codeVerifier, SCOPE_SMCB)
    }

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
    private fun gematikIDPStepSanityCheck(
        idToken: JwtContext,
        step: GematikIDPStep,
        authSession: AuthenticationSessionModel,
    ): GematikIDPStep {
        if (!idToken.jwtClaims.hasClaim("organizationName") && step == GematikIDPStep.RECEIVED_HBA_DATA) {
            val nextStep = GematikIDPStep.REQUESTED_HBA_DATA
            authSession.setAuthNote(GEMATIK_IDP_STEP, nextStep.name)
            return nextStep
        }
        return step
    }

    private fun determineIdentityProviderID(telematikId: String): String {
        return if (config.getMultipleIdentityMode()) {
            "${telematikId}_${Time.currentTimeMillis()}"
        } else {
            telematikId
        }
    }

    /**
     * Generate the Authenticator url.
     * redirectUri is our Keycloak instance /auth/realms/<realm>/broker/gematik-cidp/endpoint/result
     * [de.bdr.servko.keycloak.gematik.idp.GematikIDPEndpoint.resultPost]
     * challengePath is the central IDP
     */
    private fun generateAuthenticatorUrl(encodedState: String, codeVerifier: String, scope: String): URI {
        val redirectUri = gematikIDP.getEndpointUri(
            session,
            realm,
            null,
            config,
            RESULT_PATH
        )
        val challengePath = generateChallengePath(
            redirectUri,
            encodedState,
            codeVerifier,
            scope
        )
        val uriBuilder = handleAuthenticatorProtocol(config.getAuthenticatorUrl())
            .queryParam(CHALLENGE_PATH, challengePath)
        if (config.getNewAuthenticationFlow()) {
            uriBuilder.queryParam(CALLBACK, GematikAuthenticatorCallbackType.DIRECT.simpleName())
        }

        return uriBuilder
            .build()
    }

    private fun handleAuthenticatorProtocol(url: String): UriBuilder =
        if (url.startsWith("authenticator")) {
            UriBuilder.fromPath("//")
                .scheme("authenticator")
        } else {
            UriBuilder.fromUri(url)
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

    //we have to escape spaces already, otherwise they are replaced with + symbol,
    //which is not handled by the Authenticator app
    private fun escapeScope(scope: String) = scope.trim().replace(" ", "%20")

    /**
     * Fetch the id_token and access_token with the supplied access code.
     * @param codeVerifier previously submitted for the access code
     * @param code from IDP to authorize the request
     */
    private fun fetchIdToken(codeVerifier: String, code: String): JwtContext {
        val tokenKeyBytes: ByteArray = generateTokenKeyBytes()
        val pukIdpEnc: PublicJsonWebKey = service.getJWK(config.openidConfig.pukEncUri, config.getIdpUserAgent())

        val keyVerifier = generateKeyVerifier(Base64Url.encode(tokenKeyBytes), codeVerifier, pukIdpEnc)
            .compactSerialization

        val idJwt = service.fetchToken(
            config.tokenUrl,
            config.clientId,
            gematikIDP.getEndpointUri(session, realm, null, config, RESULT_PATH)
                .toString(),
            code,
            keyVerifier,
            config.getIdpTimeoutMs(),
            config.getIdpUserAgent()
        ).let { json ->
            // decrypt id_token
            JsonWebEncryption().apply {
                key = SecretKeySpec(tokenKeyBytes, Algorithm.AES)
                compactSerialization = json.get(OAuth2Constants.ID_TOKEN).asText()
            }.plaintextString
        }.let { decryptedIdToken ->
            // decrypted id_token has format { "njwt":"..." }
            (JSONParser().parse(decryptedIdToken) as? Map<*, *>)?.get("njwt") as? String
                ?: throw Exception("failed to extract id_token from $decryptedIdToken")
        }

        val jwks = service.getJWKS(config.openidConfig.jwksUri, config.getIdpUserAgent())

        return JwtConsumerBuilder()
            .setVerificationKey(jwks.first { it.keyId == "puk_idp_sig" }.publicKey)
            .setExpectedAudience(config.clientId)
            .setJwsProviderContext(BrainpoolCurves.PROVIDER_CONTEXT)
            .also {
                if (skipAllValidators()) {
                    it.setSkipAllValidators()
                }
            }
            .build()
            .process(idJwt)
    }

    /**
     * Generate a JWE with
     * @param tokenKey random seed
     * @param codeVerifier previously submitted for the access code
     * @param pukIdpEnc certificate from the IDP
     */
    private fun generateKeyVerifier(
        tokenKey: String,
        codeVerifier: String,
        pukIdpEnc: PublicJsonWebKey,
    ): JsonWebEncryption = JsonWebEncryption()
        .apply {
            val jwtClaims = JwtClaims().apply {
                setClaim(TOKEN_KEY, tokenKey)
                setClaim(OAuth2Constants.CODE_VERIFIER, codeVerifier)
            }.toJson()
            setPlaintext(jwtClaims)
            algorithmHeaderValue = KeyManagementAlgorithmIdentifiers.ECDH_ES
            encryptionMethodHeaderParameter = ContentEncryptionAlgorithmIdentifiers.AES_256_GCM
            key = pukIdpEnc.key
            setProviderContext(BrainpoolCurves.PROVIDER_CONTEXT)
        }

    /**
     * Store all claims in the context, so the attribute mapper can pick them up.
     */
    private fun storeDataInContext(
        contextData: MutableMap<String, Any>,
        hbaData: Map<String, Any>,
        smcbData: Map<String, Any>,
    ) {
        ContextData.values().forEach { ctx ->
            contextData[ctx.name] = when (ctx.cardType) {
                CardType.HBA -> hbaData[ctx.claim.value] ?: "UNKNOWN"
                CardType.SMCB -> smcbData[ctx.claim.value] ?: "UNKNOWN"
            }
        }
    }

    protected open fun generateTokenKeyBytes(): ByteArray = SecretGenerator.getInstance().randomBytes(32)

    protected open fun skipAllValidators(): Boolean = false
}
