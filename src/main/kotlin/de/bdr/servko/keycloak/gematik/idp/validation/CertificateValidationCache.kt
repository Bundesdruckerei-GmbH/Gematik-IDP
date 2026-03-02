package de.bdr.servko.keycloak.gematik.idp.validation

import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap

class CertificateValidationCache(
    private val cacheTtlMs: Long = DEFAULT_TTL_MS
) {
    companion object {
        const val DEFAULT_TTL_MS = (60 * 60 * 1000L)  // 1 hour
    }

    private val validatedCertificates = ConcurrentHashMap<String, Long>()

    /**
     * Checks if the certificate has been validated and is still in the cache.
     */
    fun isValidated(certificate: X509Certificate): Boolean {
        val fingerprint = getFingerprint(certificate)
        val validatedAt = validatedCertificates[fingerprint] ?: return false

        if ((System.currentTimeMillis() - validatedAt) >= cacheTtlMs) {
            validatedCertificates.remove(fingerprint)
            return false
        }
        return true
    }

    /**
     * Marks the certificate as validated.
     */
    fun markValidated(certificate: X509Certificate) {
        validatedCertificates[getFingerprint(certificate)] = System.currentTimeMillis()
    }

    /**
     * Invalidates the entire cache.
     */
    fun invalidateAll() {
        validatedCertificates.clear()
    }

    private fun getFingerprint(certificate: X509Certificate): String {
        return MessageDigest.getInstance("SHA-256")
            .digest(certificate.encoded)
            .joinToString("") { "%02x".format(it) }
    }

    fun size() = validatedCertificates.size
}
