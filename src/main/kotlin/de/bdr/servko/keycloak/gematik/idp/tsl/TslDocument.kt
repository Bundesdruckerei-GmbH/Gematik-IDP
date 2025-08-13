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
import eu.europa.esig.xmldsig.jaxb.X509DataType
import jakarta.xml.bind.JAXBElement
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal


class TslDocument(private val trustStatusListType: TrustStatusListType) {

    private val certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)

    fun getPrincipalToCertificateMap(): Map<X500Principal, X509Certificate> =
        trustStatusListType.trustServiceProviderList.trustServiceProvider
            .flatMap {
                it.tspServices.tspService
            }.flatMap { tspService ->
                tspService.serviceInformation.serviceDigitalIdentity.digitalId
                    .filter { it.x509Certificate != null && it.x509Certificate.size > 0 }
                    .map { dig ->
                        val certificate = dig.x509Certificate.inputStream().use {
                            certificateFactory.generateCertificate(it) as X509Certificate
                        }
                        certificate.subjectX500Principal to certificate
                    }
            }.toMap()


    fun getTslSigningCertificate(): X509Certificate? =
        getTslSigningCertificateElement()?.let {
            certificateFactory.generateCertificate(ByteArrayInputStream(it.value as ByteArray)) as X509Certificate
        }

    fun getTslSequenceNumber(): BigInteger = trustStatusListType.schemeInformation.tslSequenceNumber

    // eu.europa.esig.xmldsig.jaxb.KeyInfoType.getContent is a list of Object, so we have to search for the X509Certificate "manually"
    private fun getTslSigningCertificateElement(): JAXBElement<*>? =
        trustStatusListType.signature.keyInfo.content.filterIsInstance(JAXBElement::class.java)
            .map { it.value }
            .filterIsInstance<X509DataType>()
            .flatMap { it.x509IssuerSerialOrX509SKIOrX509SubjectName }
            .filterIsInstance(JAXBElement::class.java)
            .firstOrNull()
}
