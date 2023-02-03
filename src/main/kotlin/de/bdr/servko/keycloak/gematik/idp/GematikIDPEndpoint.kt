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

package de.bdr.servko.keycloak.gematik.idp

import de.bdr.servko.keycloak.gematik.idp.extension.BrainpoolCurves
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
import org.keycloak.broker.provider.util.IdentityBrokerState
import org.keycloak.common.util.Base64Url
import org.keycloak.common.util.SecretGenerator
import org.keycloak.crypto.Algorithm
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.forms.login.freemarker.model.ClientBean
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.protocol.oidc.utils.PkceUtils
import org.keycloak.services.managers.AuthenticationSessionManager
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.util.JsonSerialization
import java.net.URI
import javax.crypto.spec.SecretKeySpec
import javax.ws.rs.*
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
    private val authenticationSessionManager: AuthenticationSessionManager = AuthenticationSessionManager(session)
) {
    companion object {
        const val START_AUTH_PATH = "startAuth"
        const val RESULT_PATH = "result"

        const val CHALLENGE_PATH = "challenge_path"

        const val SCOPE_HBA = "Person_ID"
        const val SCOPE_SMCB = "Institutions_ID"
        const val TOKEN_KEY = "token_key"
        const val KEY_VERIFIER = "key_verifier"

        const val CODE_VERIFIER = "CODE_VERIFIER"
        const val GEMATIK_IDP_STEP = "GEMATIK_IDP_STEP"
        const val HBA_DATA = "HBA_DATA"
    }

    enum class GematikIDPStep {
        STARTING_AUTHENTICATOR,
        RECEIVED_HBA_DATA,
        RECEIVED_SMCB_DATA
    }

    private val logger: Logger = Logger.getLogger(this::class.java)

    /**
     * Initial call made by the user. We have access to the browser and therefore to the cookies.
     */
    @GET
    @Path(START_AUTH_PATH)
    fun startAuth(@QueryParam(OAuth2Constants.STATE) encodedState: String): Response {
        val authSession: AuthenticationSessionModel = try {
            resolveAuthSessionIgnoreCode(realm, encodedState)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        val codeVerifier = PkceUtils.generateCodeVerifier()
        authSession.setAuthNote(CODE_VERIFIER, codeVerifier)
        authSession.setAuthNote(GEMATIK_IDP_STEP, GematikIDPStep.STARTING_AUTHENTICATOR.name)

        val authenticatorUrl = generateAuthenticatorUrl(encodedState, codeVerifier, SCOPE_HBA)
        val timeoutUrl =
            gematikIDP.getEndpointUri(session, realm, decodeIdentityBrokerState(encodedState), config, "timeout")

        return forms.setAttribute("authenticatorUrl", authenticatorUrl)
            .setAttribute("timeoutUrl", timeoutUrl)
            .setAttribute("timeoutMs", config.getTimeoutMs())
            .createForm("gematik-idp.ftl")
    }

    /**
     * Called from gematik-idp.ftl after [de.bdr.servko.keycloak.gematik.idp.GematikIDPConfig.getTimeoutMs]
     * milliseconds.
     */
    @GET
    @Path("timeout")
    fun timeout(@QueryParam(OAuth2Constants.STATE) encodedState: String): Response {
        val authSession: AuthenticationSessionModel = try {
            resolveAuthSessionIgnoreCode(realm, encodedState)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        return forms.setAttribute("client", ClientBean(session, authSession.client))
            .createForm("gematik-idp-timeout.ftl")
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
        @QueryParam("error") error: String? = null,
        @QueryParam("error_details") errorDetails: String? = null,
        @QueryParam("error_uri") errorUri: String? = null,
    ): Response {
        if (code == null || encodedState == null) {
            logger.error("Authenticator returned error: $error | error-details: $errorDetails | error-uri $errorUri")
            return forms.setError("authenticator.errorIdp", errorDetails?.take(20) ?: "Unknown", errorUri)
                .createErrorPage(Response.Status.BAD_REQUEST)
        }

        val authSession: AuthenticationSessionModel = try {
            resolveAuthSessionIgnoreCode(realm, encodedState)
        } catch (e: Exception) {
            return callback.error("Failed to resolve auth session: ${e.message}")
        }

        val codeVerifier = authSession.getAuthNote(CODE_VERIFIER)
        val step = authSession.getAuthNote(GEMATIK_IDP_STEP).let {
            GematikIDPStep.valueOf(it)
        }

        val idToken = fetchIdToken(codeVerifier, code)
        return when (step) {
            GematikIDPStep.STARTING_AUTHENTICATOR -> {
                logger.debug("HBA-DATA: ${idToken.jwtClaims.claimsMap.map { (k, v) -> "$k:$v\n" }}")

                authSession.setAuthNote(HBA_DATA, JsonSerialization.writeValueAsString(idToken.jwtClaims.claimsMap))
                authSession.setAuthNote(GEMATIK_IDP_STEP, GematikIDPStep.RECEIVED_HBA_DATA.name)

                val authenticatorUrl = generateAuthenticatorUrl(encodedState, codeVerifier, SCOPE_SMCB)

                Response.status(Response.Status.FOUND)
                    .location(authenticatorUrl)
                    .build()

            }
            GematikIDPStep.RECEIVED_HBA_DATA -> {
                logger.debug("SMCB-DATA: ${idToken.jwtClaims.claimsMap.map { (k, v) -> "$k:$v\n" }}")
                authSession.setAuthNote(GEMATIK_IDP_STEP, GematikIDPStep.RECEIVED_SMCB_DATA.name)

                //we set HBA_DATA as claims map, so we know the types
                @Suppress("UNCHECKED_CAST")
                val hbaData =
                    JsonSerialization.readValue(authSession.getAuthNote(HBA_DATA), Map::class.java) as Map<String, Any>
                val smcbData = idToken.jwtClaims.claimsMap

                val telematikId = hbaData[ContextData.CONTEXT_HBA_TELEMATIK_ID.claim.value] as String
                val identityContext = BrokeredIdentityContext(telematikId)
                        .apply {
                            authenticationSession = authSession
                            idp = gematikIDP
                            idpConfig = config
                            username = telematikId
                            modelUsername = telematikId
                            storeDataInContext(contextData, hbaData, smcbData)
                        }

                callback.authenticated(identityContext)
            }
            else -> {
                callback.error("invalid step $step")
            }
        }
    }

    /**
     * Generate the Authenticator url.
     * redirectUri is our Keycloak instance /auth/realms/<realm>/broker/gematik-cidp/endpoint/result
     * [de.bdr.servko.keycloak.gematik.idp.GematikIDPEndpoint.resultPost]
     * challengePath is the central IDP
     */
    private fun generateAuthenticatorUrl(encodedState: String, codeVerifier: String, scope: String): URI {
        val redirectUri = gematikIDP.getEndpointUri(session, realm, null, config, RESULT_PATH)
        val challengePath = generateChallengePath(
            redirectUri,
            encodedState,
            codeVerifier,
            scope
        )
        return handleAuthenticatorProtocol(config.getAuthenticatorUrl())
            .queryParam(CHALLENGE_PATH, challengePath)
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
        additionalScope: String
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
            gematikIDP.getEndpointUri(session, realm, null, config, RESULT_PATH).toString(),
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
        pukIdpEnc: PublicJsonWebKey
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
        smcbData: Map<String, Any>
    ) {
        ContextData.values().forEach { ctx ->
            contextData[ctx.name] = when (ctx.cardType) {
                CardType.HBA -> hbaData[ctx.claim.value] ?: "UNKNOWN"
                CardType.SMCB -> smcbData[ctx.claim.value] ?: "UNKNOWN"
            }
        }
    }

    // copied from de.bdr.servko.keycloak.gematik.idp.GematikEndpoint.resolveAuthSessionIgnoreCode
    // We resolve the session manually to allow for refreshing the page without being bound by the active
    // session code
    private fun resolveAuthSessionIgnoreCode(
        realm: RealmModel,
        encodedState: String
    ): AuthenticationSessionModel {
        val state = decodeIdentityBrokerState(encodedState)

        val client = realm.getClientByClientId(state.clientId)
        if (client == null || !client.isEnabled) {
            throw Exception("client not found or disabled")
        }
        return authenticationSessionManager.getCurrentAuthenticationSession(realm, client, state.tabId)
    }

    private fun decodeIdentityBrokerState(encodedState: String) =
        encodedState.split(GematikIDP.STATE_DELIMITER).takeIf {
            it.size == 2
        }?.let {
            IdentityBrokerState.decoded("", it.component1(), it.component2())
        } ?: throw Exception("invalid state $encodedState")

    protected open fun generateTokenKeyBytes(): ByteArray = SecretGenerator.getInstance().randomBytes(32)

    protected open fun skipAllValidators(): Boolean = false
}
