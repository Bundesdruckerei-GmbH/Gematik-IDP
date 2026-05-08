/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
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
