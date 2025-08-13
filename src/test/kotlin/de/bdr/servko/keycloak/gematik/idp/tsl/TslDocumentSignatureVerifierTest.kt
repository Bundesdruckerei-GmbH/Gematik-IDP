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
import org.infinispan.commons.marshall.MarshallingException
import org.junit.jupiter.api.Test
import org.mockito.kotlin.*
import org.w3c.dom.Document
import org.w3c.dom.NodeList
import java.security.cert.X509Certificate
import javax.xml.crypto.dsig.XMLSignature
import javax.xml.crypto.dsig.XMLSignatureFactory
import javax.xml.crypto.dsig.XMLValidateContext

class TslDocumentSignatureVerifierTest : TslBaseTest() {

    private val underTest = TslDocumentSignatureVerifier()

    @Test
    fun `validateTslSignature - success`() {
        val (chain, _, key) = TestCertUtil.createCertificateChain()
        val generateTslXml = MockTslGenerator.generateTslDocument(chain[1])
        val signDocument = MockTslGenerator.signDocument(generateTslXml, key, chain.first())

        val verificationResult = underTest.validateTslSignature(signDocument, chain.first())


        assertThat(verificationResult.isValid).isTrue()
    }

    @Test
    fun `validateTslSignature - invalid signature`() {
        val (signXml, certificateChain) = createSignedXml(true)
        val signingCertificate = certificateChain.first()
        val document = createDocument(signXml)


        val verificationResult = underTest.validateTslSignature(document, signingCertificate)


        assertThat(verificationResult.isValid).isFalse()
        assertThat(verificationResult.errorMessage).isEqualTo("TSL signature is not valid")
    }

    @Test
    fun `validateTslSignature - no signature element - fail`() {
        val emptyNodeList = mock<NodeList> {
            on { length } doReturn 0
        }
        val document = mock<Document> {
            on { getElementsByTagNameNS(XMLSignature.XMLNS, "Signature") } doReturn emptyNodeList
        }
        val x509Certificate = mock<X509Certificate>()


        val result = underTest.validateTslSignature(document, x509Certificate)


        assertThat(result.isValid).isFalse
        assertThat(result.errorMessage).isNotNull
            .isEqualTo("No signature element found")
    }

    @Test
    fun `validateTslSignature - handle exception - failure`() {
        val (signXml, certificateChain) = createSignedXml(true)
        val signingCertificate = certificateChain.first()
        val document = createDocument(signXml)

        val signatureFactory = mock<XMLSignatureFactory>()
        whenever(signatureFactory.unmarshalXMLSignature(any<XMLValidateContext>())) doThrow MarshallingException()

        // act
        val result =
            TslDocumentSignatureVerifier(signatureFactory).validateTslSignature(document, signingCertificate)

        // assert
        assertThat(result.isValid).isFalse
        assertThat(result.errorMessage).isNotNull
            .contains("TSL document signature is not valid")
    }
}
