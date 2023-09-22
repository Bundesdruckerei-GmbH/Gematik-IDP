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

import de.bdr.servko.keycloak.gematik.idp.extension.BrainpoolCurves
import de.bdr.servko.keycloak.gematik.idp.util.RestClient
import org.jboss.logging.Logger
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.jwx.HeaderParameterNames
import org.keycloak.common.util.Base64
import org.keycloak.common.util.DerUtils
import java.io.ByteArrayInputStream
import java.security.PublicKey

open class GematikIdpOpenIDConfigurationService(private val rest: RestClient) {
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
        val openidConfigurationJWT = rest.doGet(url, userAgent)
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

    protected open fun skipAllValidators(): Boolean = false
}
