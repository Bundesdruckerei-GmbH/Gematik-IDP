/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.validation

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import java.security.cert.X509Certificate

class CertificateValidationCacheTest {

    private lateinit var cache: CertificateValidationCache

    @BeforeEach
    fun setUp() {
        cache = CertificateValidationCache(cacheTtlMs = 1000L) // 1 second TTL for tests
    }

    @Test
    fun `isValidated should return false for unknown certificate`() {
        // given
        val certificate = createMockCertificate()

        // when & then
        assertThat(cache.isValidated(certificate)).isFalse()
    }

    @Test
    fun `isValidated should return true for cached certificate`() {
        // given
        val certificate = createMockCertificate()
        cache.markValidated(certificate)

        // when & then
        assertThat(cache.isValidated(certificate)).isTrue()
    }

    @Test
    fun `isValidated should return false after TTL expires`() {
        // given
        val shortTtlCache = CertificateValidationCache(cacheTtlMs = 50L)
        val certificate = createMockCertificate()
        shortTtlCache.markValidated(certificate)

        // when
        Thread.sleep(100L)

        // then
        assertThat(shortTtlCache.isValidated(certificate)).isFalse()
    }

    @Test
    fun `invalidateAll should clear all entries`() {
        // given
        val cert1 = createMockCertificate(byteArrayOf(1, 2, 3))
        val cert2 = createMockCertificate(byteArrayOf(4, 5, 6))
        cache.markValidated(cert1)
        cache.markValidated(cert2)

        assertThat(cache.size()).isEqualTo(2)

        // when
        cache.invalidateAll()

        // then
        assertThat(cache.size()).isEqualTo(0)
        assertThat(cache.isValidated(cert1)).isFalse()
        assertThat(cache.isValidated(cert2)).isFalse()
    }

    @Test
    fun `same certificate should have same fingerprint`() {
        // given
        val encoded = byteArrayOf(1, 2, 3, 4, 5)
        val cert1 = createMockCertificate(encoded)
        val cert2 = createMockCertificate(encoded)

        cache.markValidated(cert1)

        // when & then
        assertThat(cache.isValidated(cert2)).isTrue()
    }

    @Test
    fun `different certificates should have different fingerprints`() {
        // given
        val cert1 = createMockCertificate(byteArrayOf(1, 2, 3))
        val cert2 = createMockCertificate(byteArrayOf(4, 5, 6))

        cache.markValidated(cert1)

        // when & then
        assertThat(cache.isValidated(cert1)).isTrue()
        assertThat(cache.isValidated(cert2)).isFalse()
    }

    @Test
    fun `size should return correct number of entries`() {
        // given
        assertThat(cache.size()).isEqualTo(0)

        // when
        cache.markValidated(createMockCertificate(byteArrayOf(1)))
        cache.markValidated(createMockCertificate(byteArrayOf(2)))
        cache.markValidated(createMockCertificate(byteArrayOf(3)))

        // then
        assertThat(cache.size()).isEqualTo(3)
    }

    private fun createMockCertificate(encoded: ByteArray = byteArrayOf(1, 2, 3, 4, 5)): X509Certificate {
        return mock<X509Certificate> {
            on { getEncoded() } doReturn encoded
        }
    }
}
