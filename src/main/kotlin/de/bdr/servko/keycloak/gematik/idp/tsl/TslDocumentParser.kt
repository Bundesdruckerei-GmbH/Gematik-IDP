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

import org.jboss.logging.Logger
import org.w3c.dom.Document
import org.w3c.dom.Element
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory

class TslDocumentParser {

    private val logger = Logger.getLogger(javaClass)

    // see de.gematik.pki.gemlibpki.tsl.TslUtils#createDocBuilder
    private val documentBuilderFactory = DocumentBuilderFactory.newInstance().apply {
        setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
        setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")
        isNamespaceAware = true
    }

    /**
     * Parse TSL XML String into a Document
     *
     * @param tslXml XML String to parse
     *
     * @return Document representing the XML content or {@code null} if an error occurred
     */
    fun loadDocument(tslXml: String): Document? =
        try {
            tslXml.byteInputStream().use {
                documentBuilderFactory.newDocumentBuilder().parse(it).apply {
                    xmlStandalone = true
                    markElementsAsIDAttributes(this)
                }
            }
        } catch (e: Exception) {
            logger.error("Error while parsing TSL xml", e)
            null
        }

    // Default Java XML registers only attributes with "ID" as ID attributes, but XAdES is using "Id", see <xades:SignedProperties Id="...">
    // We register those manually, so the references can be resolved.
    private fun markElementsAsIDAttributes(document: Document) {
        val elements = document.getElementsByTagNameNS("*", "*")
        for (i in 0 until elements.length) {
            val element = elements.item(i) as? Element ?: continue
            val idAttr = element.getAttributeNode("Id")
            if (idAttr != null) {
                element.setIdAttributeNode(idAttr, true)
            }
        }
    }
}
