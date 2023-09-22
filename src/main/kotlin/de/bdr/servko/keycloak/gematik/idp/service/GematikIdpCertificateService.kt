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

package de.bdr.servko.keycloak.gematik.idp.service

import com.fasterxml.jackson.databind.JsonNode
import de.bdr.servko.keycloak.gematik.idp.extension.BrainpoolCurves
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import de.bdr.servko.keycloak.gematik.idp.util.GematikIDPUtil
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals
import de.bdr.servko.keycloak.gematik.idp.util.RestClient
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jboss.logging.Logger
import org.jose4j.json.JsonUtil
import org.jose4j.json.internal.json_simple.parser.JSONParser
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwk.PublicJsonWebKey
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.jwt.consumer.JwtContext
import org.keycloak.OAuth2Constants
import org.keycloak.common.util.Base64Url
import org.keycloak.common.util.SecretGenerator
import org.keycloak.crypto.Algorithm
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import javax.crypto.spec.SecretKeySpec

open class GematikIdpCertificateService(
    private val realm: RealmModel,
    private val session: KeycloakSession,
    private val config: GematikIDPConfig,
    private val rest: RestClient = RestClient(session),
) {
    private val logger = Logger.getLogger(this::class.java)

    /**
     * Fetch the id_token and access_token with the supplied access code.
     * @param codeVerifier previously submitted for the access code
     * @param code from IDP to authorize the request
     */
    fun fetchIdToken(codeVerifier: String, code: String): JwtContext {
        val tokenKeyBytes: ByteArray = generateTokenKeyBytes()
        val pukIdpEnc: PublicJsonWebKey = this.getJWK(config.openidConfig.pukEncUri, config.getIdpUserAgent())

        val keyVerifier = GematikIDPUtil.generateKeyVerifier(Base64Url.encode(tokenKeyBytes), codeVerifier, pukIdpEnc)
            .compactSerialization

        val idJwt = this.fetchToken(
            config.tokenUrl,
            config.clientId,
            GematikIDPUtil.getEndpointUri(session, realm, null, config, GematikIdpLiterals.RESULT_PATH)
                .toString(),
            code,
            keyVerifier,
            config.getIdpTimeoutMs(),
            config.getIdpUserAgent()
        ).let { json ->
            // decrypt id_token
            JsonWebEncryption().apply {
                key = SecretKeySpec(tokenKeyBytes, Algorithm.AES)
                compactSerialization = json[OAuth2Constants.ID_TOKEN].asText()
            }.plaintextString
        }.let { decryptedIdToken ->
            // decrypted id_token has format { "njwt":"..." }
            (JSONParser().parse(decryptedIdToken) as? Map<*, *>)?.get("njwt") as? String
                ?: throw Exception("failed to extract id_token from $decryptedIdToken")
        }

        val jwks = this.getJWKS(config.openidConfig.jwksUri, config.getIdpUserAgent())

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
     * Fetch the id_token and access_token from IDP
     * @param idpUrl token endpoint of IDP
     * @param clientId client registered at the IDP
     * @param redirectUrl redirect to our Keycloak
     * @param code access code supplied from Authenticator
     * @param keyVerifier JWE of initial code_verifier encrypted with IDP JWK enc
     */
    private fun fetchToken(
        idpUrl: String,
        clientId: String,
        redirectUrl: String,
        code: String,
        keyVerifier: String,
        timoutMs: Int,
        userAgent: String,
    ): JsonNode = rest.doPost(
        idpUrl, mapOf(
            OAuth2Constants.CLIENT_ID to clientId,
            OAuth2Constants.REDIRECT_URI to redirectUrl,
            OAuth2Constants.CODE to code,
            GematikIdpLiterals.KEY_VERIFIER to keyVerifier,
            OAuth2Constants.GRANT_TYPE to OAuth2Constants.AUTHORIZATION_CODE
        ), timoutMs, userAgent
    )

    /**
     * Fetch the JWK from the IDP
     * @param jwkUri url extract from openid configuration "uri_puk_idp_enc" or "uri_puk_idp_sig"
     */
    private fun getJWK(jwkUri: String, userAgent: String): PublicJsonWebKey = PublicJsonWebKey.Factory.newPublicJwk(
        rest.doGet(jwkUri, userAgent), BouncyCastleProvider.PROVIDER_NAME
    )

    /**
     * Fetch JWKS from the IDP
     * @param jwksUri jwks endpoint
     *
     * We do not use jose4j, because org.jose4j.jwk.JsonWebKeySet do not support BC provider.
     */
    private fun getJWKS(jwksUri: String, userAgent: String): List<PublicJsonWebKey> = rest.doGet(jwksUri, userAgent).let {
        //extract keys from JWKS
        (JsonUtil.parseJson(it)[JsonWebKeySet.JWK_SET_MEMBER_NAME] as List<*>).filterIsInstance<Map<String, Any>>()
    }.map {
        PublicJsonWebKey.Factory.newPublicJwk(it, BouncyCastleProvider.PROVIDER_NAME)
    }

    protected open fun generateTokenKeyBytes(): ByteArray = SecretGenerator.getInstance().randomBytes(32)

    protected open fun skipAllValidators(): Boolean = false
}
