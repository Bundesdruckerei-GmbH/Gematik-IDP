/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.tsl

import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.keycloak.truststore.TruststoreProvider
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.w3c.dom.Document
import java.security.KeyStore
import java.security.Security
import java.security.cert.X509Certificate

abstract class TslBaseTest {

    init {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    val keyStore: KeyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
        load(null)
    }
    val truststoreProvider = mock<TruststoreProvider> {
        on { truststore } doReturn keyStore
    }

    fun createSignedXml(invalidSignature: Boolean = false): Pair<String, List<X509Certificate>> {
        val (chain, _, key) = TestCertUtil.createCertificateChain()
        val leaf = chain.first()
        val intermediate = chain[1]

        val tslDoc = MockTslGenerator.generateTslDocument(intermediate)
        val signedTslDoc = MockTslGenerator.signDocument(tslDoc, key, leaf)
        val tslXml = MockTslGenerator.documentToString(signedTslDoc, invalidSignature)
        return tslXml to chain
    }

    fun createDocument(signXml: String = createSignedXml().first): Document {
        val document = TslDocumentParser().loadDocument(signXml)
        assertThat(document).isNotNull
        return document!!
    }

    fun createTrustStatusList(): Pair<TrustStatusListType, List<X509Certificate>> {
        val (signXml, certificateChain) = createSignedXml()
        val document = createDocument(signXml)

        val trustStatusLit = TslDocumentUnmarshaller().unmarshall(document)
        assertThat(trustStatusLit).isNotNull

        return trustStatusLit!! to certificateChain
    }

    fun mockKeycloakTruststore(trustedCert: X509Certificate) {
        keyStore.setCertificateEntry("root", trustedCert)
        whenever(truststoreProvider.rootCertificates).doReturn(
            mapOf(trustedCert.subjectX500Principal to listOf(trustedCert))
        )
    }
}
