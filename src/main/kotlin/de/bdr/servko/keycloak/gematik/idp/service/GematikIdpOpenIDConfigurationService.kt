/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.service

import de.bdr.servko.keycloak.gematik.idp.extension.BrainpoolCurves
import de.bdr.servko.keycloak.gematik.idp.tsl.TslCertificateVerifierProvider
import de.bdr.servko.keycloak.gematik.idp.util.RestClient
import org.jboss.logging.Logger
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.jwx.HeaderParameterNames
import org.keycloak.common.util.Base64
import org.keycloak.common.util.DerUtils
import org.keycloak.models.KeycloakSession
import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

open class GematikIdpOpenIDConfigurationService(
    session: KeycloakSession,
    private val client: RestClient = RestClient(session),
    private val tslCertificateVerifierProvider: TslCertificateVerifierProvider = session.getProvider(
        TslCertificateVerifierProvider::class.java
    ),
) {

    private val logger = Logger.getLogger(this::class.java)

    /**
     * Discovery Document is a JWS (JSON Web Signature).
     * We extract the payload and verify it with the x5c value from the JOSE header,
     * which is generated with BP256R1.
     *
     * [org.keycloak.jose.jws.JWSInput] does not support BP256R1 algorithm
     * We do not use jose4j to get the X509 certificate, because it does not use BouncyCastle as provider.
     */
    fun getOpenIDConfiguration(url: String, userAgent: String, validateSigningCertificate: Boolean): JwtClaims {
        val openidConfigurationJWT = client.doGet(url, userAgent)
        val signingCertificate: X509Certificate =
            JsonWebSignature.fromCompactSerialization(openidConfigurationJWT).run {
                //extract base64 encoded x5c certificate from header
                Base64.decode(
                    (headers.getObjectHeaderValue(HeaderParameterNames.X509_CERTIFICATE_CHAIN) as List<*>).filterIsInstance<String>()
                        .first()
                )
            }.let { x5cBytes ->
                //use org.keycloak.common.util.DerUtils to generate the key, since it's using BC
                ByteArrayInputStream(x5cBytes).use {
                    DerUtils.decodeCertificate(it)
                }
            }

        if (validateSigningCertificate) {
            val verifyCertificate = tslCertificateVerifierProvider.verifyCertificate(signingCertificate)
            if (!verifyCertificate.isValid) {
                throw CertificateException(verifyCertificate.errorMessage)
            }
        } else {
            logger.info("Validation of the signing certificate of the OpenID configuration is disabled.")
        }

        val jwtClaims = JwtConsumerBuilder().setVerificationKey(signingCertificate.publicKey)
            .setJwsProviderContext(BrainpoolCurves.PROVIDER_CONTEXT)
            .also {
                if (skipAllValidators()) {
                    it.setSkipAllValidators()
                }
            }.build().process(openidConfigurationJWT).jwtClaims

        return jwtClaims
    }

    protected open fun skipAllValidators(): Boolean = false
}
