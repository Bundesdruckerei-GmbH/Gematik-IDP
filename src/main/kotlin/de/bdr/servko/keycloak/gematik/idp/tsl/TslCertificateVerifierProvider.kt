/*
 * Copyright 2025 Bundesdruckerei GmbH and/or its affiliates
 * and other contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.bdr.servko.keycloak.gematik.idp.tsl

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jboss.logging.Logger
import org.keycloak.provider.Provider
import org.keycloak.truststore.TruststoreProvider
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.cert.*
import javax.security.auth.x500.X500Principal

data class CertificateVerificationResult(
    val isValid: Boolean,
    val certificate: X509Certificate? = null,
    val trustAnchor: TrustAnchor? = null,
    val errorMessage: String? = null,
)

open class TslCertificateVerifierProvider(
    private val truststoreProvider: TruststoreProvider,
    private val repository: TslCertificateRepository,
) : Provider {

    private val logger = Logger.getLogger(javaClass)

    /**
     * Verify a certificate with the full certificate chain provided by the TSL and Keycloak truststore.
     *
     * @param certToValidate certificate to validate
     * @param certificateByPrincipalSupplier
     * @return verification result
     */
    fun verifyCertificate(
        certToValidate: X509Certificate,
        certificateByPrincipalSupplier: (X500Principal) -> X509Certificate? = { repository.getCertificateByPrincipal(it) },
    ): CertificateVerificationResult =
        try {
            logger.debug("Verifying certificate ${certToValidate.subjectX500Principal.name} with issuer ${certToValidate.issuerX500Principal.name}")
            certToValidate.checkValidity()
            verifyCertificateChain(
                buildCertificateChain(certToValidate, certificateByPrincipalSupplier),
                truststoreProvider.truststore
            ).also {
                logger.debug("Certificate ${certToValidate.subjectX500Principal.name} is valid '${it.isValid}' with trust anchor '${it.trustAnchor?.trustedCert?.subjectX500Principal}'")
            }
        } catch (e: CertificateNotYetValidException) {
            handleCertificateNotYetValidException(certToValidate, e)
        } catch (e: CertificateExpiredException) {
            handleCertificateExpiredException(certToValidate, e)
        } catch (e: CertPathValidatorException) {
            handleCertPathValidatorException(certToValidate, e)
        }

    /**
     * Verify a certificate with the certificates provided by the TSL and Keycloak truststore.
     *
     * This should only be used for validating the TSL signing certificate!
     *
     * @param certToValidate certificate to validate
     * @param certificateMap temporary map from TSL XML
     * @return verification result
     */
    fun verifyTslSigningCertificateWithTemporaryTslData(
        certToValidate: X509Certificate,
        certificateMap: Map<X500Principal, X509Certificate>,
    ): CertificateVerificationResult = verifyCertificate(certToValidate) { certificateMap[it] }

    override fun close() {
        // noop
    }

    private fun buildCertificateChain(
        certificate: X509Certificate,
        certificateByPrincipalSupplier: (X500Principal) -> X509Certificate?,
        chain: MutableList<X509Certificate> = mutableListOf(),
    ): List<X509Certificate> {
        chain += certificate

        logger.debug("Certificate chain: ${chain.joinToString { it.subjectX500Principal.name }}")

        return if (isSelfSigned(certificate)) {
            chain
        } else {
            // Find issuer certificate and continue chain
            certificateByPrincipalSupplier(certificate.issuerX500Principal)
                ?.let { buildCertificateChain(it, certificateByPrincipalSupplier, chain) }
                ?: handleIssuerNotFound(certificate.issuerX500Principal, chain)
        }
    }

    private fun isSelfSigned(certificate: X509Certificate): Boolean =
        try {
            // check for self-signed/root certificate
            certificate.verify(certificate.publicKey, BouncyCastleProvider.PROVIDER_NAME)
            certificate.subjectX500Principal == certificate.issuerX500Principal
        } catch (_: GeneralSecurityException) {
            // ignore exception as it is expected for non-root certificates
            false
        }

    private fun handleIssuerNotFound(issuerX500Principal: X500Principal, chain: MutableList<X509Certificate>): MutableList<X509Certificate> {
        logger.warn("Issuer '$issuerX500Principal' not found for chain ${chain.joinToString { it.subjectX500Principal.name }}")
        return chain
    }

    private fun verifyCertificateChain(
        certificateChain: List<X509Certificate>,
        trustStore: KeyStore,
    ): CertificateVerificationResult {
        val certPath = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
            .generateCertPath(certificateChain)
        val params = PKIXParameters(trustStore).apply {
            isRevocationEnabled = false
            sigProvider = BouncyCastleProvider.PROVIDER_NAME
        }

        val validatorResult = CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME)
            .validate(certPath, params) as PKIXCertPathValidatorResult
        return CertificateVerificationResult(
            true,
            certificate = certificateChain.first(),
            trustAnchor = validatorResult.trustAnchor
        )
    }

    private fun handleCertificateNotYetValidException(
        certToValidate: X509Certificate,
        e: CertificateNotYetValidException,
    ): CertificateVerificationResult =
        CertificateVerificationResult(
            false,
            errorMessage = "TSL certificate is not yet valid: ${e.message}",
        ).also {
            logger.warn("Certificate '${certToValidate.subjectX500Principal}' is not yet valid.", e)
        }

    private fun handleCertificateExpiredException(
        certToValidate: X509Certificate,
        e: CertificateExpiredException,
    ): CertificateVerificationResult =
        CertificateVerificationResult(
            false,
            errorMessage = "TSL certificate is expired: ${e.message}",
        ).also {
            logger.warn("Certificate '${certToValidate.subjectX500Principal}' is expired.", e)
        }

    private fun handleCertPathValidatorException(
        certToValidate: X509Certificate,
        e: CertPathValidatorException,
    ): CertificateVerificationResult =
        CertificateVerificationResult(
            false,
            errorMessage = "TSL certificate path is not valid: ${e.message}",
        ).also {
            logger.warn("Certificate path for '${certToValidate.subjectX500Principal}' is not valid", e)
        }
}
