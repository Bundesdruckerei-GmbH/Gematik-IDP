/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.validation

import de.bdr.servko.keycloak.gematik.idp.tsl.CertificateVerificationResult
import de.bdr.servko.keycloak.gematik.idp.tsl.TslCertificateVerifierProvider
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.*
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

class GematikIdpCertificateValidatorProviderTest {

    private lateinit var tslVerifierMock: TslCertificateVerifierProvider
    private lateinit var cache: CertificateValidationCache
    private lateinit var underTest: GematikIdpCertificateValidatorProvider

    @BeforeEach
    fun setUp() {
        tslVerifierMock = mock()
        cache = CertificateValidationCache()
        underTest = GematikIdpCertificateValidatorProvider(tslVerifierMock, cache)
    }

    @Test
    fun `should throw exception when certificate is null`() {
        assertThatThrownBy { underTest.validateTokenSignerCertificate(null) }
            .isInstanceOf(CertificateException::class.java)
            .hasMessageContaining("No certificate in puk_idp_sig")
    }

    @Test
    fun `should validate certificate and cache on success`() {
        // given
        val certificate = createMockCertificate()
        whenever(tslVerifierMock.verifyCertificate(any(), any()))
            .thenReturn(CertificateVerificationResult(isValid = true))

        // when
        underTest.validateTokenSignerCertificate(certificate)

        // then
        verify(tslVerifierMock).verifyCertificate(eq(certificate), any())
        assertThat(cache.isValidated(certificate)).isTrue()
    }

    @Test
    fun `should skip validation when certificate is cached`() {
        // given
        val certificate = createMockCertificate()
        cache.markValidated(certificate)

        // when
        underTest.validateTokenSignerCertificate(certificate)

        // then
        verify(tslVerifierMock, never()).verifyCertificate(any(), any())
    }

    @Test
    fun `should throw exception when validation fails`() {
        // given
        val certificate = createMockCertificate()
        whenever(tslVerifierMock.verifyCertificate(any(), any()))
            .thenReturn(CertificateVerificationResult(
                isValid = false,
                errorMessage = "Issuer certificate not found in TSL"
            ))

        // when & then
        assertThatThrownBy { underTest.validateTokenSignerCertificate(certificate) }
            .isInstanceOf(CertificateException::class.java)
            .hasMessageContaining("Issuer certificate not found in TSL")

        assertThat(cache.isValidated(certificate)).isFalse()
    }

    @Test
    fun `should invalidate cache`() {
        // given
        val certificate = createMockCertificate()
        cache.markValidated(certificate)
        assertThat(cache.isValidated(certificate)).isTrue()

        // when
        underTest.invalidateCache()

        // then
        assertThat(cache.isValidated(certificate)).isFalse()
    }

    private fun createMockCertificate(encoded: ByteArray = byteArrayOf(1, 2, 3, 4, 5)): X509Certificate {
        return mock<X509Certificate> {
            on { getEncoded() } doReturn encoded
        }
    }
}
