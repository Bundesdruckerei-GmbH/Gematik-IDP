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

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.keycloak.models.KeycloakSession
import org.keycloak.truststore.TruststoreProvider
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.math.BigInteger
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

class TslCertificateRepositoryTest : TslBaseTest() {

    private val keycloakSession = mock<KeycloakSession> {
        on { getProvider(TruststoreProvider::class.java) } doReturn truststoreProvider
    }

    private val principal = X500Principal("CN=localhost")
    private val x509Certificate = mock<X509Certificate> {
        on { subjectX500Principal } doReturn principal
    }

    private val underTest = TslCertificateRepository()

    @Test
    fun `updateDataFromTsl - success`() {
        val keycloakRootCertificate = mockKeycloakTrustStore()


        underTest.updateDataFromTsl(keycloakSession, mapOf(principal to x509Certificate), BigInteger.ONE)


        val certificate = underTest.getCertificateByPrincipal(principal)
        assertThat(certificate).isNotNull
            .isEqualTo(x509Certificate)
            .extracting { it!!.subjectX500Principal }
            .isEqualTo(principal)

        val rootCertificate = underTest.getCertificateByPrincipal(keycloakRootCertificate.subjectX500Principal)
        assertThat(rootCertificate).isNotNull
            .isEqualTo(keycloakRootCertificate)
            .extracting { it!!.subjectX500Principal }
            .isEqualTo(keycloakRootCertificate.subjectX500Principal)
    }

    @Test
    fun `updateDataFromTsl - same sequence number - update skipped`() {
        underTest.updateDataFromTsl(keycloakSession, mapOf(principal to x509Certificate), BigInteger.ZERO)


        assertThat(underTest.getCertificateByPrincipal(principal)).isNull()
    }

    @Test
    fun `updateDataFromTsl - remove old data`() {
        underTest.updateDataFromTsl(keycloakSession, mapOf(principal to x509Certificate), BigInteger.ONE)

        val testPrincipal = X500Principal("CN=test")
        val testCertificate = mock<X509Certificate> {
            on { subjectX500Principal } doReturn testPrincipal
        }


        underTest.updateDataFromTsl(keycloakSession, mapOf(testPrincipal to testCertificate), BigInteger.TWO)


        assertThat(underTest.getCertificateByPrincipal(principal)).isNull()

        val certificate = underTest.getCertificateByPrincipal(testPrincipal)
        assertThat(certificate).isNotNull
            .isEqualTo(testCertificate)
            .extracting { it!!.subjectX500Principal }
            .isEqualTo(testPrincipal)
    }

    @Test
    fun `createCertificateMap - success`() {
        val rootCertificate = mockKeycloakTrustStore()


        val result = underTest.createCertificateMap(keycloakSession, mapOf(principal to x509Certificate))


        assertThat(result).hasSize(2)
        assertThat(result[rootCertificate.subjectX500Principal]).isNotNull
            .isEqualTo(rootCertificate)
        assertThat(result[principal]).isNotNull
            .isEqualTo(x509Certificate)
    }

    @Test
    fun `getKeycloakTrustedCertificates - success`() {
        val rootCertificate = mockKeycloakTrustStore()


        underTest.updateDataFromTsl(keycloakSession, mapOf(principal to x509Certificate), BigInteger.ONE)


        assertThat(underTest.getCertificateByPrincipal(principal)).isNotNull
        assertThat(underTest.getCertificateByPrincipal(rootCertificate.subjectX500Principal)).isNotNull
    }

    private fun mockKeycloakTrustStore(): X509Certificate {
        val rootPrincipal = X500Principal("CN=root")
        val rootCertificate = mock<X509Certificate> {
            on { subjectX500Principal } doReturn rootPrincipal
        }
        val testPrincipal = X500Principal("CN=test")
        whenever(truststoreProvider.rootCertificates).doReturn(
            mapOf(
                rootPrincipal to listOf(rootCertificate),
                testPrincipal to emptyList()
            )
        )
        return rootCertificate
    }

}
