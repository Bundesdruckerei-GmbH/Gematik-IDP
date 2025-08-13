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

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jboss.logging.Logger
import org.w3c.dom.Document
import org.w3c.dom.Element
import java.security.Security
import java.security.cert.X509Certificate
import javax.xml.crypto.dsig.XMLSignature
import javax.xml.crypto.dsig.XMLSignatureFactory
import javax.xml.crypto.dsig.dom.DOMValidateContext

class TslDocumentSignatureVerifier(
    private val xmlSignateFactory: XMLSignatureFactory = XMLSignatureFactory.getInstance("DOM"),
) {

    private val logger = Logger.getLogger(javaClass)

    /**
     * Validate the signature of the TSL XML with the corresponding signing certificate.
     *
     * @param document TSL XML document to validate
     * @param signingCertificate certificate which was used to sign the TSL XML document
     *
     * @return certification result true or false if signature is invalid
     */
    fun validateTslSignature(
        document: Document,
        signingCertificate: X509Certificate,
    ): CertificateVerificationResult =
        getSignatureElement(document)?.let {
            try {
                val domValidateContext = DOMValidateContext(signingCertificate.publicKey, it).apply {
                    // IMPORTANT: inject Bouncy Castle provider to handle EC curves
                    setProperty(
                        "org.jcp.xml.dsig.internal.dom.SignatureProvider",
                        Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)
                    )
                }
                logger.debug("Validating TSL signature with ${signingCertificate.subjectX500Principal.name}")

                val isValid = xmlSignateFactory.unmarshalXMLSignature(domValidateContext)
                    .validate(domValidateContext)

                logger.debug("TSL signature is valid: $isValid")

                CertificateVerificationResult(
                    isValid,
                    signingCertificate,
                    errorMessage = if (!isValid) {
                        "TSL signature is not valid"
                    } else {
                        null
                    }
                )
            } catch (e: Exception) {
                handleException(signingCertificate, e)
            }
        } ?: CertificateVerificationResult(false, errorMessage = "No signature element found")

    private fun getSignatureElement(document: Document): Element? =
        document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
            .takeIf {
                it.length > 0
            }?.item(0) as Element?

    private fun handleException(certificate: X509Certificate, e: Exception): CertificateVerificationResult =
        CertificateVerificationResult(
            false,
            errorMessage = "TSL document signature is not valid ${e.message}"
        ).also {
            logger.error(
                "Error while validating TSL document signature with '${certificate.subjectX500Principal}",
                e
            )
        }
}
