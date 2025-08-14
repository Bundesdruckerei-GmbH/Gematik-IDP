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
