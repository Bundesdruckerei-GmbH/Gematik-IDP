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
