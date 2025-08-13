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
import org.junit.jupiter.api.assertDoesNotThrow
import org.keycloak.connections.httpclient.HttpClientProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.timer.TimerProvider
import org.keycloak.truststore.TruststoreProvider
import org.mockito.kotlin.*

class TslProviderFactoryTest : TslBaseTest() {

    private val timerProvider = mock<TimerProvider>()
    private val session = mock<KeycloakSession> {
        on { getProvider(TruststoreProvider::class.java) } doReturn truststoreProvider
        on { getProvider(TimerProvider::class.java) } doReturn timerProvider
    }
    private val sessionFactory = mock<KeycloakSessionFactory> {
        on { create() } doReturn session
    }

    private val tslRepository = spy<TslCertificateRepository>()
    private val tslDocumentSignatureVerifier = mock<TslDocumentSignatureVerifier> {}
    private val tslDocumentParser = mock<TslDocumentParser> {}
    private val tslDocumentUnmarshaller = spy<TslDocumentUnmarshaller> {}
    private val tslDownloadClient = mock<TslDownloadClient> {}

    private val underTest = TslProviderFactory(
        tslRepository,
        tslDocumentSignatureVerifier,
        tslDocumentParser,
        tslDocumentUnmarshaller
    ) { tslDownloadClient }

    @Test
    fun getId() {
        assertThat(underTest.getId()).isEqualTo("tsl-provider-factory")
    }

    @Test
    fun create() {
        assertThat(underTest.create(session)).isNotNull.isInstanceOf(TslCertificateVerifierProvider::class.java)
    }

    @Test
    fun dependsOn() {
        assertThat(underTest.dependsOn()).contains(HttpClientProvider::class.java, TruststoreProvider::class.java)
    }

    @Test
    fun postInit() {
        val (chain, trustAnchor, key) = TestCertUtil.createCertificateChain()
        val leaf = chain.first()
        val intermediate = chain[1]

        val tslDoc = MockTslGenerator.generateTslDocument(intermediate)
        val signedTslDoc = MockTslGenerator.signDocument(tslDoc, key, leaf)
        val signXml = MockTslGenerator.documentToString(signedTslDoc)

        whenever(tslDownloadClient.fetchTsl()) doReturn signXml
        whenever(tslDocumentParser.loadDocument(signXml)) doReturn signedTslDoc
        whenever(
            tslDocumentSignatureVerifier.validateTslSignature(
                any(),
                any()
            )
        ) doReturn CertificateVerificationResult(true, leaf, trustAnchor)
        mockKeycloakTruststore(trustAnchor.trustedCert)


        underTest.postInit(sessionFactory)


        assertThat(tslRepository.getCertificateByPrincipal(intermediate.subjectX500Principal)).isEqualTo(intermediate)
        verify(timerProvider).scheduleTask(any(), any(), eq("GematikIdpTslUpdate"))
        verify(session).close()
    }

    @Test
    fun `postInit - invalid tsl signature`() {
        val (chain, trustAnchor, key) = TestCertUtil.createCertificateChain()
        val leaf = chain.first()
        val intermediate = chain[1]

        val tslDoc = MockTslGenerator.generateTslDocument(intermediate)
        val signedTslDoc = MockTslGenerator.signDocument(tslDoc, key, leaf)
        val signXml = MockTslGenerator.documentToString(signedTslDoc, true)

        whenever(tslDownloadClient.fetchTsl()) doReturn signXml
        whenever(tslDocumentParser.loadDocument(signXml)) doReturn signedTslDoc
        whenever(
            tslDocumentSignatureVerifier.validateTslSignature(
                any(),
                any()
            )
        ) doReturn CertificateVerificationResult(false, errorMessage = "TSL signature is not valid")
        mockKeycloakTruststore(trustAnchor.trustedCert)


        underTest.postInit(sessionFactory)


        verify(tslRepository, never()).updateDataFromTsl(eq(session), any(), any())
        verify(timerProvider).scheduleTask(any(), any(), eq("GematikIdpTslUpdate"))
        verify(session).close()
    }

    @Test
    fun `postInit - invalid tsl signing certificate`() {
        val (chain, trustAnchor, key) = TestCertUtil.createCertificateChain(makeIntermediateExpired = true)
        val leaf = chain.first()
        val intermediate = chain[1]

        val tslDoc = MockTslGenerator.generateTslDocument(intermediate)
        val signedTslDoc = MockTslGenerator.signDocument(tslDoc, key, leaf)
        val signXml = MockTslGenerator.documentToString(signedTslDoc, true)

        whenever(tslDownloadClient.fetchTsl()) doReturn signXml
        whenever(tslDocumentParser.loadDocument(signXml)) doReturn signedTslDoc
        mockKeycloakTruststore(trustAnchor.trustedCert)


        underTest.postInit(sessionFactory)


        verify(tslRepository, never()).updateDataFromTsl(eq(session), any(), any())
        verify(timerProvider).scheduleTask(any(), any(), eq("GematikIdpTslUpdate"))
        verify(session).close()
    }

    @Test
    fun `postInit - document parser error`() {
        val (chain, _, key) = TestCertUtil.createCertificateChain()
        val leaf = chain.first()
        val intermediate = chain[1]

        val tslDoc = MockTslGenerator.generateTslDocument(intermediate)
        val signedTslDoc = MockTslGenerator.signDocument(tslDoc, key, leaf)
        val signXml = MockTslGenerator.documentToString(signedTslDoc, true)

        whenever(tslDownloadClient.fetchTsl()) doReturn signXml
        whenever(tslDocumentParser.loadDocument(signXml)) doReturn null


        underTest.postInit(sessionFactory)


        verify(tslRepository, never()).updateDataFromTsl(eq(session), any(), any())
        verify(timerProvider).scheduleTask(any(), any(), eq("GematikIdpTslUpdate"))
        verify(session).close()
    }

    @Test
    fun `postInit - unmarshall error`() {
        val (chain, _, key) = TestCertUtil.createCertificateChain()
        val leaf = chain.first()
        val intermediate = chain[1]

        val tslDoc = MockTslGenerator.generateTslDocument(intermediate)
        val signedTslDoc = MockTslGenerator.signDocument(tslDoc, key, leaf)
        val signXml = MockTslGenerator.documentToString(signedTslDoc, true)

        whenever(tslDownloadClient.fetchTsl()) doReturn signXml
        whenever(tslDocumentParser.loadDocument(signXml)) doReturn signedTslDoc
        whenever(tslDocumentUnmarshaller.unmarshall(signedTslDoc)) doReturn null


        underTest.postInit(sessionFactory)


        verify(tslRepository, never()).updateDataFromTsl(eq(session), any(), any())
        verify(timerProvider).scheduleTask(any(), any(), eq("GematikIdpTslUpdate"))
        verify(session).close()
    }

    @Test
    fun `postInit - schedule periodic update - failure`() {
        val cert = TestCertUtil.generateCertificate()
        keyStore.setCertificateEntry("root", cert)
        whenever(timerProvider.scheduleTask(any(), any(), any())) doThrow RuntimeException()


        assertDoesNotThrow { underTest.postInit(sessionFactory) }


        verify(session).close()
    }

    @Test
    fun close() {
        underTest.postInit(sessionFactory)


        underTest.close()


        verify(timerProvider).cancelTask("GematikIdpTslUpdate")
    }

    @Test
    fun `close - cancel task - failure`() {
        underTest.postInit(sessionFactory)
        whenever(timerProvider.cancelTask("GematikIdpTslUpdate")) doThrow RuntimeException()


        assertDoesNotThrow { underTest.close() }


        verify(timerProvider).cancelTask("GematikIdpTslUpdate")
        verify(session, times(2)).close()
    }

    @Test
    fun `close - no scheduled task - failure`() {
        whenever(timerProvider.scheduleTask(any(), any(), any())) doThrow RuntimeException()
        underTest.postInit(sessionFactory)


        assertDoesNotThrow { underTest.close() }


        verify(session).close()
    }
}
