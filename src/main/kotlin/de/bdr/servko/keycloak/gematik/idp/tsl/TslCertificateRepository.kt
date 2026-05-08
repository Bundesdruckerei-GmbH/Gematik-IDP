/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.tsl

import org.jboss.logging.Logger
import org.keycloak.models.KeycloakSession
import org.keycloak.truststore.TruststoreProvider
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference
import javax.security.auth.x500.X500Principal

/**
 * This class represents the list of certificates included in the TSL and Keycloak truststore.
 *
 * The TSL file contains all end- and intermediate certificates of the gematik, but not the root certificates.
 * The root certificates are stored on the filesystem and added to the Keycloak truststore on server start.
 */
class TslCertificateRepository() {

    private val logger = Logger.getLogger(javaClass)

    private var tslSequenceNumber = AtomicReference(BigInteger.ZERO)
    private val certificates = ConcurrentHashMap<X500Principal, X509Certificate>()

    /**
     * Update the certificates with new data from the TSL file,
     * if a new sequence number is available.
     *
     * @param session: Keycloak session to retrieve the trusted certificates
     * @param tslData: Mapped content of the TSL file
     * @param newSequenceNumber: Sequence number of the new TSL file
     */
    fun updateDataFromTsl(
        session: KeycloakSession,
        tslData: Map<X500Principal, X509Certificate>,
        newSequenceNumber: BigInteger,
    ) {
        if (tslSequenceNumber.get() == newSequenceNumber) {
            logger.info("Tsl sequence number $newSequenceNumber matches $tslSequenceNumber, skipping update")
            return
        }

        val trustedCertificates = getKeycloakTrustedCertificates(session)
        certificates.keys.retainAll(trustedCertificates.keys + tslData.keys)
        certificates.putAll(createCertificateMap(session, tslData, trustedCertificates))
        tslSequenceNumber.set(newSequenceNumber)
        logger.info("Updated ${certificates.keys.size} certificates")
    }

    /**
     * Create a map of principal to certificate with the passed tslData and certificates from Keycloak truststore.
     */
    fun createCertificateMap(
        session: KeycloakSession,
        tslData: Map<X500Principal, X509Certificate>,
        keycloakTrustedCertificates: Map<X500Principal, X509Certificate> = getKeycloakTrustedCertificates(session),
    ): Map<X500Principal, X509Certificate> =
        buildMap {
            putAll(tslData)
            putAll(keycloakTrustedCertificates)
        }

    /**
     * Loop up the certificate by its principal.
     *
     * @param principal principal to search for in the stored certificates map.
     *
     * @return certificate with the principal or {@code null} if no matching entry was found.
     */
    fun getCertificateByPrincipal(principal: X500Principal): X509Certificate? = certificates[principal]

    fun getSequenceNumber(): AtomicReference<BigInteger> = tslSequenceNumber

    private fun getKeycloakTrustedCertificates(session: KeycloakSession): Map<X500Principal, X509Certificate> =
        session.getProvider(TruststoreProvider::class.java).let { truststoreProvider ->
            buildMap {
                putAll(truststoreProvider.rootCertificates.firstCerts())
                putAll(truststoreProvider.intermediateCertificates.firstCerts())
            }
        }

    private fun Map<X500Principal, List<X509Certificate>>.firstCerts(): Map<X500Principal, X509Certificate> =
        filterValues { it.isNotEmpty() }.mapValues { (_, certs) -> certs.first() }
}
