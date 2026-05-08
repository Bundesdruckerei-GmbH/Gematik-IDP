/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.tsl

import org.apache.xml.security.Init
import org.apache.xml.security.utils.Constants
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.w3c.dom.Document
import org.w3c.dom.Element
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Security
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.*
import javax.xml.crypto.dsig.*
import javax.xml.crypto.dsig.dom.DOMSignContext
import javax.xml.crypto.dsig.dom.DOMValidateContext
import javax.xml.crypto.dsig.keyinfo.KeyInfo
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec
import javax.xml.crypto.dsig.spec.TransformParameterSpec
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.OutputKeys
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import kotlin.test.assertTrue

object MockTslGenerator {

    init {
        Init.init()
    }

    private const val NAMESPACE_URI = "http://uri.etsi.org/02231/v2#"
    private val docFactory = DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = true
    }

    fun generateTslDocument(cert: X509Certificate): Document {
        val doc = docFactory.newDocumentBuilder().newDocument()

        val trustServiceStatusListElement = createTrustServiceStatusListElement(doc)
        doc.appendChild(trustServiceStatusListElement)

        val schemeInfo = createSchemeInformationElement(doc)
        trustServiceStatusListElement.appendChild(schemeInfo)

        val providers = createTrustServiceProviderList(doc, cert)
        trustServiceStatusListElement.appendChild(providers)

        return doc
    }

    fun signDocument(doc: Document, keyPair: KeyPair, cert: X509Certificate): Document {
        // Prepare XML document
        val xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM")

        // Reference to the root document
        val reference = xmlSignatureFactory.newReference(
            "", // entire document
            xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null),
            listOf(
                xmlSignatureFactory.newTransform(Transform.ENVELOPED, null as TransformParameterSpec?),
                xmlSignatureFactory.newTransform(CanonicalizationMethod.EXCLUSIVE, null as TransformParameterSpec?)
            ),
            null, "Reference-1"
        )

        // SignedInfo
        val signedInfo = xmlSignatureFactory.newSignedInfo(
            xmlSignatureFactory.newCanonicalizationMethod(
                CanonicalizationMethod.EXCLUSIVE,
                null as C14NMethodParameterSpec?
            ),
            xmlSignatureFactory.newSignatureMethod(SignatureMethod.ECDSA_SHA256, null),
            listOf(reference)
        )

        // KeyInfo
        val keyInfoFactory: KeyInfoFactory = xmlSignatureFactory.keyInfoFactory
        val x509Data = keyInfoFactory.newX509Data(listOf(cert))
        val keyInfo: KeyInfo = keyInfoFactory.newKeyInfo(listOf(x509Data))

        // Add XAdES QualifyingProperties manually
        val objectNode = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "ds:Object")
        val xadesNs = "http://uri.etsi.org/01903/v1.3.2#"
        val qProps = doc.createElementNS(xadesNs, "xades:QualifyingProperties")
        qProps.setAttribute("Target", "#Signature-1")

        val signedProps = doc.createElementNS(xadesNs, "xades:SignedProperties")
        signedProps.setAttribute("Id", "SignedProperties-1")

        val signedSignatureProps = doc.createElementNS(xadesNs, "xades:SignedSignatureProperties")

        // SigningTime
        val signingTime = doc.createElementNS(xadesNs, "xades:SigningTime")
        val now = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(Date())
        signingTime.textContent = now

        signedSignatureProps.appendChild(signingTime)

        // Digest of signing certificate
        val signingCert = doc.createElementNS(xadesNs, "xades:SigningCertificate")
        val certElem = doc.createElementNS(xadesNs, "xades:Cert")

        val digestAlgElem = doc.createElementNS(xadesNs, "xades:CertDigest")
        val digestMethodElem = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "ds:DigestMethod")
        digestMethodElem.setAttribute("Algorithm", DigestMethod.SHA256)
        val digestValueElem = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "ds:DigestValue")

        val digest = MessageDigest.getInstance("SHA-256")
        val encoded = digest.digest(cert.encoded)
        val digestBase64 = Base64.getEncoder().encodeToString(encoded)
        digestValueElem.textContent = digestBase64

        val issuerSerial = doc.createElementNS(xadesNs, "xades:IssuerSerial")
        val issuerName = doc.createElementNS(xadesNs, "xades:X509IssuerName")
        issuerName.textContent = cert.issuerX500Principal.name
        val serialNumber = doc.createElementNS(xadesNs, "xades:X509SerialNumber")
        serialNumber.textContent = cert.serialNumber.toString()
        issuerSerial.appendChild(issuerName)
        issuerSerial.appendChild(serialNumber)

        digestAlgElem.appendChild(digestMethodElem)
        digestAlgElem.appendChild(digestValueElem)
        certElem.appendChild(digestAlgElem)
        certElem.appendChild(issuerSerial)
        signingCert.appendChild(certElem)
        signedSignatureProps.appendChild(signingCert)

        signedProps.appendChild(signedSignatureProps)
        qProps.appendChild(signedProps)
        objectNode.appendChild(qProps)


        val context = DOMSignContext(keyPair.private, doc.documentElement).apply {
            this.defaultNamespacePrefix = "ds"
            setProperty(
                "org.jcp.xml.dsig.internal.dom.SignatureProvider",
                Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)
            )
        }
        val xmlSignature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo)
        xmlSignature.sign(context)
        val signatureElement = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature").item(0) as Element
        signatureElement.appendChild(objectNode)

        assertTrue("XML signature should be valid") { validateSignature(doc, keyPair.public, xmlSignatureFactory) }

        return doc
    }

    fun documentToString(doc: Document, invalidateSignature: Boolean = false): String {
        // Serialize XML
        val transformer = TransformerFactory.newInstance().newTransformer().apply {
            if (invalidateSignature) {
                // change xml after signing, which fails signature check
                setOutputProperty(OutputKeys.INDENT, "yes")
            }
        }
        val out = ByteArrayOutputStream()
        transformer.transform(DOMSource(doc), StreamResult(out))
        return out.toString("UTF-8")
    }

    fun validateSignature(
        doc: Document,
        cert: PublicKey,
        xmlSignatureFactory: XMLSignatureFactory,
    ): Boolean {
        val signatureElement = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature").item(0) as Element
        val validateContext = DOMValidateContext(cert, signatureElement).apply {
            setProperty(
                "org.jcp.xml.dsig.internal.dom.SignatureProvider",
                Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)
            )
        }
        return xmlSignatureFactory.unmarshalXMLSignature(validateContext)
            .validate(validateContext)
    }

    private fun createTrustServiceProviderList(doc: Document, cert: X509Certificate): Element {
        val providers = doc.createElementNS(NAMESPACE_URI, "TrustServiceProviderList")
        val provider = doc.createElementNS(NAMESPACE_URI, "TrustServiceProvider")

        val tspInfo = createTSPInformation(doc)
        provider.appendChild(tspInfo)

        val services = doc.createElementNS(NAMESPACE_URI, "TSPServices")
        val service = doc.createElementNS(NAMESPACE_URI, "TSPService")
        val serviceInfo = doc.createElementNS(NAMESPACE_URI, "ServiceInformation")
        serviceInfo.appendChild(doc.createElementNS(NAMESPACE_URI, "ServiceTypeIdentifier").apply {
            textContent = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC"
        })

        val identity = createServiceDigitalIdentity(doc, cert)
        serviceInfo.appendChild(identity)

        service.appendChild(serviceInfo)
        services.appendChild(service)
        provider.appendChild(services)
        providers.appendChild(provider)
        return providers
    }

    private fun createTSPInformation(doc: Document): Element {
        val tspInfo = doc.createElementNS(NAMESPACE_URI, "TSPInformation")
        val tspName = doc.createElementNS(NAMESPACE_URI, "TSPName")
        val name = doc.createElementNS(NAMESPACE_URI, "Name")
            .apply {
                setAttributeNS("http://www.w3.org/XML/1998/namespace", "xml:lang", "DE")
                textContent = "Mock CA"
            }
        tspName.appendChild(name)
        tspInfo.appendChild(tspName)
        return tspInfo
    }

    private fun createServiceDigitalIdentity(doc: Document, cert: X509Certificate): Element {
        val identity = doc.createElementNS(NAMESPACE_URI, "ServiceDigitalIdentity")
        val digitalId = doc.createElementNS(NAMESPACE_URI, "DigitalId")
        val x509El = doc.createElementNS(NAMESPACE_URI, "X509Certificate").apply {
            textContent = Base64.getEncoder().encodeToString(cert.encoded)
        }
        digitalId.appendChild(x509El)
        identity.appendChild(digitalId)
        return identity
    }

    private fun createSchemeInformationElement(doc: Document): Element {
        return doc.createElementNS(NAMESPACE_URI, "SchemeInformation")
            .apply {
                appendChild(doc.createElementNS(NAMESPACE_URI, "TSLVersionIdentifier").apply { textContent = "5" })
                appendChild(doc.createElementNS(NAMESPACE_URI, "TSLSequenceNumber").apply { textContent = "1" })
                appendChild(
                    doc.createElementNS(NAMESPACE_URI, "TSLType")
                        .apply { textContent = "http://uri.etsi.org/TSLType/generic" })
                appendChild(doc.createElementNS(NAMESPACE_URI, "SchemeTerritory").apply { textContent = "DE" })
            }
    }

    private fun createTrustServiceStatusListElement(doc: Document): Element {
        return doc.createElementNS(NAMESPACE_URI, "TrustServiceStatusList")
            .apply {
                setAttribute("xmlns", NAMESPACE_URI)
                setAttribute("TSLTag", "http://uri.etsi.org/02231/TSLTag")
            }
    }
}
