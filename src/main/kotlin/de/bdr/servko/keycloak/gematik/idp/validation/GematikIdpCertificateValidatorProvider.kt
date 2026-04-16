/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.validation

import de.bdr.servko.keycloak.gematik.idp.tsl.TslCertificateVerifierProvider
import org.jboss.logging.Logger
import org.keycloak.provider.Provider
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

class GematikIdpCertificateValidatorProvider (
    private val tslCertificateVerifierProvider: TslCertificateVerifierProvider,
    private val cache: CertificateValidationCache,
) : Provider {

    private val logger = Logger.getLogger(this::class.java)

    fun validateTokenSignerCertificate(certificate: X509Certificate?) {
        val cert = certificate ?: throw CertificateException("No certificate in puk_idp_sig")

        if (cache.isValidated(cert)) {
            logger.debug("Certificate validation skipped - found in cache")
            return
        }

        val result = tslCertificateVerifierProvider.verifyCertificate(cert)
        if (!result.isValid) {
            throw CertificateException(result.errorMessage)
        }

        cache.markValidated(cert)
        logger.debug("Certificate validated and cached")
    }

    /**
     * Invalidate the cache (to be called after a TSL update)
     */
    fun invalidateCache() {
        cache.invalidateAll()
    }

    override fun close() {
        //
    }
}
