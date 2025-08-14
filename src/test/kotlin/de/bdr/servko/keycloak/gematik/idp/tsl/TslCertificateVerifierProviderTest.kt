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
import java.math.BigInteger

class TslCertificateVerifierProviderTest : TslBaseTest() {
    private val keycloakSession = mock<KeycloakSession> {
        on { getProvider(TruststoreProvider::class.java) } doReturn truststoreProvider
    }

    private val repository = TslCertificateRepository()
    private val underTest = TslCertificateVerifierProvider(truststoreProvider, repository)

    @Test
    fun `verifyCertificate - success`() {
        val (chain, trustAnchor, _) = TestCertUtil.createCertificateChain()
        mockKeycloakTruststore(trustAnchor.trustedCert)

        repository.updateDataFromTsl(keycloakSession, chain.associateBy { it.subjectX500Principal }, BigInteger.ONE)
        val certToValidate = chain.first()


        val verificationResult = underTest.verifyCertificate(certToValidate)


        assertThat(verificationResult.isValid).isTrue()
        assertThat(verificationResult.certificate).isEqualTo(certToValidate)
        assertThat(verificationResult.trustAnchor).isNotNull
            .extracting { it!!.trustedCert }
            .isEqualTo(trustAnchor.trustedCert)
    }

    @Test
    fun `verifyCertificate - invalid intermediate certificate - not a ca`() {
        val (chain, trustAnchor, _) = TestCertUtil.createCertificateChain(makeIntermediateInvalid = true)
        mockKeycloakTruststore(trustAnchor.trustedCert)

        repository.updateDataFromTsl(keycloakSession, chain.associateBy { it.subjectX500Principal }, BigInteger.ONE)


        val verificationResult = underTest.verifyCertificate(chain.first())


        assertThat(verificationResult.isValid).isFalse
        assertThat(verificationResult.errorMessage).isNotNull
            .isEqualTo("TSL certificate path is not valid: Not a CA certificate")
    }

    @Test
    fun `verifyCertificate - invalid intermediate certificate - expired`() {
        val (chain, trustAnchor, _) = TestCertUtil.createCertificateChain(makeIntermediateExpired = true)
        mockKeycloakTruststore(trustAnchor.trustedCert)

        repository.updateDataFromTsl(keycloakSession, chain.associateBy { it.subjectX500Principal }, BigInteger.ONE)


        val verificationResult = underTest.verifyCertificate(chain.first())


        assertThat(verificationResult.isValid).isFalse
        assertThat(verificationResult.errorMessage).isNotNull
            .contains("Could not validate certificate: certificate expired on")
    }

    @Test
    fun `verifyCertificate - invalid intermediate certificate - not yet valid`() {
        val (chain, trustAnchor, _) = TestCertUtil.createCertificateChain(makeIntermediateNotYetValid = true)
        mockKeycloakTruststore(trustAnchor.trustedCert)

        repository.updateDataFromTsl(keycloakSession, chain.associateBy { it.subjectX500Principal }, BigInteger.ONE)


        val verificationResult = underTest.verifyCertificate(chain.first())


        assertThat(verificationResult.isValid).isFalse
        assertThat(verificationResult.errorMessage).isNotNull
            .contains("Could not validate certificate: certificate not valid till")
    }

    @Test
    fun `verifyCertificate - invalid certificate - not yet valid`() {
        val rootCert = TestCertUtil.generateCertificate(notYetValid = true)


        val verificationResult = underTest.verifyCertificate(rootCert)


        assertThat(verificationResult.isValid).isFalse()
        assertThat(verificationResult.errorMessage).isNotNull
            .contains("TSL certificate is not yet valid: certificate not valid till")
    }

    @Test
    fun `verifyCertificate - invalid certificate - expired`() {
        val rootCert = TestCertUtil.generateCertificate(expired = true)


        val verificationResult = underTest.verifyCertificate(rootCert)


        assertThat(verificationResult.isValid).isFalse
        assertThat(verificationResult.errorMessage).isNotNull
            .contains("TSL certificate is expired: certificate expired on")
    }

    @Test
    fun `verifyCertificate - root certificate - missing`() {
        val (chain, _, _) = TestCertUtil.createCertificateChain()
        mockKeycloakTruststore(chain[1])
        repository.updateDataFromTsl(keycloakSession, chain.associateBy { it.subjectX500Principal }, BigInteger.ONE)


        val verificationResult = underTest.verifyCertificate(chain.first())


        assertThat(verificationResult.isValid).isFalse
        assertThat(verificationResult.errorMessage).isNotNull
            .contains("TSL certificate path is not valid: Trust anchor for certification path not found.")
    }

    @Test
    fun `verifyTslSigningCertificateWithTemporaryTslData - success`() {
        val (chain, trustAnchor, _) = TestCertUtil.createCertificateChain()
        mockKeycloakTruststore(trustAnchor.trustedCert)
        val certToValidate = chain.first()


        val verificationResult = underTest.verifyTslSigningCertificateWithTemporaryTslData(
            certToValidate,
            chain.associateBy { it.subjectX500Principal })


        assertThat(verificationResult.isValid).isTrue()
        assertThat(verificationResult.certificate).isEqualTo(certToValidate)
        assertThat(verificationResult.trustAnchor).isNotNull
            .extracting { it!!.trustedCert }
            .isEqualTo(trustAnchor.trustedCert)
    }
}
