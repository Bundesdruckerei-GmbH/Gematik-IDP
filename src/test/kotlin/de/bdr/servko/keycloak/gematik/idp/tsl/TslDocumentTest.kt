/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.tsl

import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType
import eu.europa.esig.xmldsig.jaxb.KeyInfoType
import eu.europa.esig.xmldsig.jaxb.SignatureType
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import java.math.BigInteger

class TslDocumentTest : TslBaseTest() {

    @Test
    fun `getPrincipalToCertificateMap - success`() {
        val (trustStatusList, certificateChain) = createTrustStatusList()
        val signingCert = certificateChain[1]

        val tslDocument = TslDocument(trustStatusList)


        val result = tslDocument.getPrincipalToCertificateMap()


        assertThat(result).hasSize(1)
        assertThat(result[signingCert.subjectX500Principal])
            .isNotNull
            .isEqualTo(signingCert)
    }


    @Test
    fun `getTslSigningCertificate - success`() {
        val (trustStatusList, certificateChain) = createTrustStatusList()
        val signingCert = certificateChain.first()

        val tslDocument = TslDocument(trustStatusList)


        val result = tslDocument.getTslSigningCertificate()


        assertThat(result).isNotNull
            .isEqualTo(signingCert)
    }

    @Test
    fun `getTslSigningCertificate - no signing certificate element - failure`() {
        val keyInfoType = mock<KeyInfoType> {
            on { content } doReturn emptyList()
        }
        val signatureType = mock<SignatureType> {
            on { keyInfo } doReturn keyInfoType
        }
        val trustStatusListType = mock<TrustStatusListType> {
            on { signature } doReturn signatureType
        }
        val tslDocument = TslDocument(trustStatusListType)


        val result = tslDocument.getTslSigningCertificate()


        assertThat(result).isNull()
    }

    @Test
    fun `getTslSequenceNumber - success`() {
        val (trustStatusList, _) = createTrustStatusList()

        val tslDocument = TslDocument(trustStatusList)


        val result = tslDocument.getTslSequenceNumber()


        assertThat(result).isEqualTo(BigInteger.ONE)
    }
}
