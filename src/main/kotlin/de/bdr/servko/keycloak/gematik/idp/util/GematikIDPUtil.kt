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

package de.bdr.servko.keycloak.gematik.idp.util

import de.bdr.servko.keycloak.gematik.idp.extension.BrainpoolCurves
import de.bdr.servko.keycloak.gematik.idp.model.*
import de.bdr.servko.keycloak.gematik.idp.rest.GematikIDPResource
import org.jboss.logging.MDC
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers
import org.jose4j.jwk.PublicJsonWebKey
import org.jose4j.jwt.JwtClaims
import org.keycloak.OAuth2Constants
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.services.resources.IdentityBrokerService
import org.keycloak.services.resources.RealmsResource
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.util.JsonSerialization
import java.net.URI

class GematikIDPUtil {
    companion object {
        fun getGematikIdpStepFrom(authSession: AuthenticationSessionModel): GematikIDPStep =
            authSession.getAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP)?.let {
                GematikIDPStep.valueOf(it)
            } ?: GematikIDPStep.ERROR

        fun getCertificateDataFromAuthNote(
            authSession: AuthenticationSessionModel,
            authNote: String,
        ): Map<String, Any>? =
            authSession.getAuthNote(authNote)?.let {
                //we set the IDP DATA as claims map, so we know the types
                @Suppress("UNCHECKED_CAST")
                JsonSerialization.readValue(it, Map::class.java) as Map<String, Any>?
            }

        fun setAuthenticatorVersionInAuthSession(
            version: AuthenticatorVersion,
            authSession: AuthenticationSessionModel,
        ) {
            if (!version.isNullOrEmpty()) {
                authSession.setAuthNote(GematikIdpLiterals.AUTHENTICATOR_VERSION, version.toString())
            }
        }

        fun addAuthenticatorVersionToMdc(version: AuthenticatorVersion) {
            MDC.put(GematikIdpLiterals.AUTHENTICATOR_VERSION, version.toString())
        }

        /**
         * Generate a JWE with
         * @param tokenKey random seed
         * @param codeVerifier previously submitted for the access code
         * @param pukIdpEnc certificate from the IDP
         */
        fun generateKeyVerifier(
            tokenKey: String,
            codeVerifier: String,
            pukIdpEnc: PublicJsonWebKey,
        ): JsonWebEncryption = JsonWebEncryption()
            .apply {
                val jwtClaims = JwtClaims().apply {
                    setClaim(GematikIdpLiterals.TOKEN_KEY, tokenKey)
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
        fun storeDataInContext(
            contextData: MutableMap<String, Any>,
            hbaData: Map<String, Any>? = null,
            smcbData: Map<String, Any>? = null,
        ) {
            ContextData.entries.forEach { ctx ->
                contextData[ctx.name] = when (ctx.cardType) {
                    CardType.HBA -> hbaData?.get(ctx.claim.value) ?: "UNKNOWN"
                    CardType.SMCB -> smcbData?.get(ctx.claim.value) ?: "UNKNOWN"
                }
            }
        }

        fun getEndpointUri(
            session: KeycloakSession,
            realm: RealmModel,
            state: GematikIDPState?,
            config: GematikIDPConfig,
            endpoint: String,
        ): URI =
            RealmsResource.brokerUrl(session.context.uri)
                .path(IdentityBrokerService::class.java, "getEndpoint")
                .path(GematikIDPResource::class.java, endpoint)
                .apply {
                    //C-IDP state has pattern ^[_\\-a-zA-Z0-9]{1,512}$
                    state?.let {
                        queryParam(OAuth2Constants.STATE, it.encode())
                    }
                }
                .build(realm.name, config.alias)
    }

}
