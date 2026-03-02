package de.bdr.servko.keycloak.gematik.idp.validation

import de.bdr.servko.keycloak.gematik.idp.tsl.CertificateVerificationResult
import de.bdr.servko.keycloak.gematik.idp.tsl.TslCertificateVerifierProvider
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.keycloak.models.KeycloakSession
import org.mockito.Mockito.times
import org.mockito.Mockito.verify
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.security.cert.X509Certificate

class GematikIdpCertificateValidatorProviderFactoryTest {

    private lateinit var underTest: GematikIdpCertificateValidatorProviderFactory
    private lateinit var sessionMock: KeycloakSession
    private lateinit var tslProviderMock: TslCertificateVerifierProvider

    @BeforeEach
    fun setUp() {
        tslProviderMock = mock<TslCertificateVerifierProvider>() {

        }
        sessionMock = mock<KeycloakSession> {
            on { getProvider(TslCertificateVerifierProvider::class.java) } doReturn tslProviderMock
        }

        underTest = GematikIdpCertificateValidatorProviderFactory()
    }

    @Test
    fun `getId should return correct provider id`() {
        assertThat(underTest.id).isEqualTo(GematikIdpCertificateValidatorProviderFactory.PROVIDER_ID)
    }

    @Test
    fun `create should return provider instance`() {
        // when
        val provider = underTest.create(sessionMock)

        // then
        assertThat(provider).isNotNull()
        assertThat(provider).isInstanceOf(GematikIdpCertificateValidatorProvider::class.java)
    }

    @Test
    fun `create should throw exception when TslCertificateVerifierProvider is not available`() {
        // given
        whenever(sessionMock.getProvider(TslCertificateVerifierProvider::class.java)).thenReturn(null)

        // when & then
        assertThatThrownBy { underTest.create(sessionMock) }
            .isInstanceOf(IllegalStateException::class.java)
            .hasMessageContaining("TslCertificateVerifierProvider not available")
    }

    @Test
    fun `multiple create calls should share the same cache`() {
        // given
        val provider1 = underTest.create(sessionMock)
        val provider2 = underTest.create(sessionMock)

        val certificate = mock<X509Certificate> {
            on { encoded } doReturn byteArrayOf(1, 2, 3)
        }

        whenever(tslProviderMock.verifyCertificate(any(), any())).thenReturn(
            CertificateVerificationResult(isValid = true)
        )

        // when - validate with provider1
        provider1.validateTokenSignerCertificate(certificate)

        // then - provider2 should see it as cached (no verification call)
        provider2.validateTokenSignerCertificate(certificate)

        // verify only called once (first validation), second was cached
        verify(tslProviderMock, times(1)).verifyCertificate(any(), any())
    }

    @Test
    fun `close should clear shared cache`() {
        // given
        val provider = underTest.create(sessionMock)
        val certificate = mock<X509Certificate> {
            on { encoded } doReturn byteArrayOf(1, 2, 3)
        }

        whenever(tslProviderMock.verifyCertificate(any(), any())).thenReturn(
            CertificateVerificationResult(isValid = true)
        )

        // validate and cache
        provider.validateTokenSignerCertificate(certificate)

        // when
        underTest.close()

        // then - should validate again after cache invalidation
        provider.validateTokenSignerCertificate(certificate)

        verify(tslProviderMock, times(2)).verifyCertificate(any(), any())
    }
}
