/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.tsl

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.*

object TestCertUtil {

    fun generateBrainpoolKeyPair(curve: String = "brainpoolP256r1"): KeyPair =
        KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME).apply {
            initialize(ECGenParameterSpec(curve), SecureRandom())
        }.generateKeyPair()


    fun generateCertificate(
        isCa: Boolean = false,
        invalidCa: Boolean = false,
        expired: Boolean = false,
        notYetValid: Boolean = false,
    ): X509Certificate {
        val keyPair = generateBrainpoolKeyPair()
        return generateCertificate(keyPair, "CN=Test", keyPair, "CN=Test", isCa, invalidCa, expired, notYetValid)
    }

    fun generateCertificate(
        subjectKeyPair: KeyPair,
        subjectDn: String,
        issuerKeyPair: KeyPair,
        issuerDn: String,
        isCa: Boolean,
        invalidCa: Boolean = false, // if true, don't set CA or use wrong signer
        expired: Boolean = false,
        notYetValid: Boolean = false,
    ): X509Certificate {
        val now = Date()
        val validity = 60 * 1000
        val notAfter =
            if (expired) {
                Date(now.time - validity)
            } else {
                Date(now.time + validity)
            }
        val notBefore = if (notYetValid) {
            Date(now.time + validity)
        } else {
            now
        }
        val serial = BigInteger.valueOf(System.nanoTime())

        val builder = JcaX509v3CertificateBuilder(
            X500Name(issuerDn),
            serial,
            notBefore,
            notAfter,
            X500Name(subjectDn),
            subjectKeyPair.public
        )

        if (!invalidCa) {
            builder.addExtension(
                Extension.basicConstraints,
                true,
                BasicConstraints(isCa)
            )
        } else {
            // Invalid intermediate: mark as not CA
            builder.addExtension(
                Extension.basicConstraints,
                true,
                BasicConstraints(false)
            )
        }

        val signer = JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(issuerKeyPair.private)

        val certHolder = builder.build(signer)

        return JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(certHolder)
    }

    fun createCertificateChain(
        makeIntermediateInvalid: Boolean = false,
        makeIntermediateExpired: Boolean = false,
        makeIntermediateNotYetValid: Boolean = false,
    ): Triple<List<X509Certificate>, TrustAnchor, KeyPair> {
        // Root
        val rootKey = generateBrainpoolKeyPair()
        val rootDn = "CN=TestRoot"
        val rootCert = generateCertificate(rootKey, rootDn, rootKey, rootDn, isCa = true)

        val trustAnchor = TrustAnchor(rootCert, null)

        // Intermediate
        val interKey = generateBrainpoolKeyPair()
        val interDn = "CN=Intermediate"

        val intermediateCert = generateCertificate(
            interKey, interDn,
            rootKey, rootCert.subjectX500Principal.name,
            isCa = true,
            invalidCa = makeIntermediateInvalid,
            expired = makeIntermediateExpired,
            notYetValid = makeIntermediateNotYetValid,
        )

        // End-entity
        val leafKey = generateBrainpoolKeyPair()
        val leafDn = "CN=Leaf"

        val leafCert = generateCertificate(
            leafKey, leafDn,
            interKey, intermediateCert.subjectX500Principal.name,
            isCa = false
        )

        val chain = listOf(leafCert, intermediateCert)
        return Triple(chain, trustAnchor, leafKey)
    }
}
