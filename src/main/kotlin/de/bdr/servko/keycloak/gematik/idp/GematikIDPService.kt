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

import com.fasterxml.jackson.databind.JsonNode
import de.bdr.servko.keycloak.gematik.idp.exception.IdpUnavailableException
import de.bdr.servko.keycloak.gematik.idp.exception.SessionNotFoundException
import de.bdr.servko.keycloak.gematik.idp.extension.AuthenticationSessionAdapterExtension
import de.bdr.servko.keycloak.gematik.idp.extension.BrainpoolCurves
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jboss.logging.Logger
import org.jose4j.json.JsonUtil
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.PublicJsonWebKey
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.jwx.HeaderParameterNames
import org.keycloak.OAuth2Constants
import org.keycloak.broker.provider.util.IdentityBrokerState
import org.keycloak.broker.provider.util.SimpleHttp
import org.keycloak.common.util.Base64
import org.keycloak.common.util.DerUtils
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.services.managers.AuthenticationSessionManager
import org.keycloak.sessions.AuthenticationSessionModel
import java.io.ByteArrayInputStream
import java.security.PublicKey
import javax.ws.rs.core.HttpHeaders

open class GematikIDPService(
    private val session: KeycloakSession,
    private val authenticationSessionManager: AuthenticationSessionManager = AuthenticationSessionManager(session),
    private val authenticationSessionAdapterExtension: AuthenticationSessionAdapterExtension = AuthenticationSessionAdapterExtension(
        session,
        session.context.realm
    )
) {
    private val logger = Logger.getLogger(this::class.java)

    /**
     * Discovery Document is a JWS (JSON Web Signature).
     * We extract the payload and verify it with the x5c value from the JOSE header,
     * which is generated with BP256R1.
     *
     * [org.keycloak.jose.jws.JWSInput.JWSInput] does not support BP256R1 algorithm
     * We do not use jose4j to get the X509 certificate, because it does not use BouncyCastle as provider.
     */
    fun getOpenIDConfiguration(url: String, userAgent: String): JwtClaims {
        val openidConfigurationJWT = doGet(url, userAgent)
        val verificationKey: PublicKey = JsonWebSignature.fromCompactSerialization(openidConfigurationJWT).run {
            //extract base64 encoded x5c certificate from header
            Base64.decode(
                (headers.getObjectHeaderValue(HeaderParameterNames.X509_CERTIFICATE_CHAIN) as List<*>).filterIsInstance<String>()
                    .first()
            )
        }.let { x5cBytes ->
            //use org.keycloak.common.util.DerUtils to generate the key, since it's using BC
            ByteArrayInputStream(x5cBytes).use {
                DerUtils.decodeCertificate(it).publicKey
            }
        }

        val jwtClaims = JwtConsumerBuilder().setVerificationKey(verificationKey)
            .setJwsProviderContext(BrainpoolCurves.PROVIDER_CONTEXT).also {
                if (skipAllValidators()) {
                    it.setSkipAllValidators()
                }
            }.build().process(openidConfigurationJWT).jwtClaims

        return jwtClaims
    }

    /**
     * Fetch the JWK from the IDP
     * @param jwkUri url extract from openid configuration "uri_puk_idp_enc" or "uri_puk_idp_sig"
     */
    fun getJWK(jwkUri: String, userAgent: String): PublicJsonWebKey = PublicJsonWebKey.Factory.newPublicJwk(
        doGet(jwkUri, userAgent), BouncyCastleProvider.PROVIDER_NAME
    )

    /**
     * Fetch JWKS from the IDP
     * @param jwksUri jwks endpoint
     *
     * We do not use jose4j, because org.jose4j.jwk.JsonWebKeySet do not support BC provider.
     */
    fun getJWKS(jwksUri: String, userAgent: String): List<PublicJsonWebKey> = doGet(jwksUri, userAgent).let {
        //extract keys from JWKS
        (JsonUtil.parseJson(it)[JsonWebKeySet.JWK_SET_MEMBER_NAME] as List<*>).filterIsInstance<Map<String, Any>>()
    }.map {
        PublicJsonWebKey.Factory.newPublicJwk(it, BouncyCastleProvider.PROVIDER_NAME)
    }

    /**
     * Fetch the id_token and access_token from IDP
     * @param idpUrl token endpoint of IDP
     * @param clientId client registered at the IDP
     * @param redirectUrl redirect to our Keycloak
     * @param code access code supplied from Authenticator
     * @param keyVerifier JWE of initial code_verifier encrypted with IDP JWK enc
     */
    fun fetchToken(
        idpUrl: String,
        clientId: String,
        redirectUrl: String,
        code: String,
        keyVerifier: String,
        timoutMs: Int,
        userAgent: String,
    ): JsonNode = doPost(
        idpUrl, mapOf(
            OAuth2Constants.CLIENT_ID to clientId,
            OAuth2Constants.REDIRECT_URI to redirectUrl,
            OAuth2Constants.CODE to code,
            GematikIDPEndpoint.KEY_VERIFIER to keyVerifier,
            OAuth2Constants.GRANT_TYPE to OAuth2Constants.AUTHORIZATION_CODE
        ), timoutMs, userAgent
    )

    open fun doGet(idpUrl: String, userAgent: String): String {
        val response = SimpleHttp.doGet(idpUrl, session).header(HttpHeaders.USER_AGENT, userAgent).asResponse().also {
            handleErrorResponse(it, idpUrl, "GET")
        }

        return response.asString()
    }

    private fun handleErrorResponse(response: SimpleHttp.Response, idpUrl: String, method: String) {
        if (response.status >= 500) {
            logger.warn("IDP $idpUrl returned status code ${response.status} with body ${response.asString()}")
            throw IdpUnavailableException("IDP $idpUrl returned status code ${response.status} with body ${response.asString()}")
        } else {
            logger.info("$method $idpUrl response ${response.status}")
        }
    }

    open fun doPost(
        idpUrl: String,
        paramMap: Map<String, String> = emptyMap(),
        timoutMs: Int,
        userAgent: String,
    ): JsonNode =
        SimpleHttp.doPost(idpUrl, session).connectTimeoutMillis(timoutMs).connectionRequestTimeoutMillis(timoutMs)
            .socketTimeOutMillis(timoutMs).header(HttpHeaders.USER_AGENT, userAgent).apply {
                paramMap.map { param(it.key, it.value) }
            }.asResponse().also {
                handleErrorResponse(it, idpUrl, "POST")
            }.asJson()

    protected open fun skipAllValidators(): Boolean = false

    /**
     * @adapted de.bdr.servko.keycloak.gematik.idp.GematikEndpoint.resolveAuthSessionIgnoreCode
     * We resolve the session manually to allow for refreshing the page without being bound by the active
     * session code.
     * Additionally, when no session is found via the Authentication Session Manager, try to retrieve the session
     * directly from the IniniSpan-cache. This is necessary, because the Gematik-Authenticator doesn't send the session
     * cookie containing the ID of the root authentication session when calling our plugin.
     *
     * @param realm
     * @param encodedState
     * @return
     */
    fun resolveAuthSessionFromEncodedState(
        realm: RealmModel,
        encodedState: String,
    ): AuthenticationSessionModel {
        val state = decodeIdentityBrokerState(encodedState)

        val client = realm.getClientByClientId(state.clientId)
        if (client == null || !client.isEnabled) {
            throw Exception("client not found or disabled")
        }

        return authenticationSessionManager.getCurrentAuthenticationSession(realm, client, state.tabId)
            ?: authenticationSessionAdapterExtension.getAuthenticationSessionFor(
                state.tabId,
                client
            ) ?: throw authSessionNotFound(encodedState)
    }

    fun decodeIdentityBrokerState(encodedState: String) =
        encodedState.split(GematikIDP.STATE_DELIMITER).takeIf {
            it.size == 2
        }?.let {
            IdentityBrokerState.decoded("", null, it.component1(), it.component2())
        } ?: throw Exception("invalid state $encodedState")

    private fun authSessionNotFound(encodedState: String?): SessionNotFoundException {
        val realm = session.context.realm
        logger.error("AuthenticationSessionModel not found for state $encodedState and realm ${realm.name}")
        return SessionNotFoundException("AuthenticationSessionModel not found for state $encodedState")
    }
}
