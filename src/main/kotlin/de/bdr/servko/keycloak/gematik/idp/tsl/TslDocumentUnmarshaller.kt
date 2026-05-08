/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.tsl

import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType
import jakarta.xml.bind.JAXBContext
import org.jboss.logging.Logger
import org.w3c.dom.Document

class TslDocumentUnmarshaller {

    private val logger = Logger.getLogger(javaClass)

    private val jAXBContext = JAXBContext.newInstance(TrustStatusListType::class.java)

    /**
     * Unmarshall Document into TrustStatusListType
     *
     * @param document Document to unmarshall
     *
     * @return TrustStatusListType or {@code null} if an error occurred
     */
    fun unmarshall(document: Document): TrustStatusListType? =
        try {
            jAXBContext.createUnmarshaller()
                .unmarshal(document.firstChild, TrustStatusListType::class.java).value
        } catch (e: Exception) {
            logger.error("Error while unmarshalling TSL document", e)
            null
        }
}
