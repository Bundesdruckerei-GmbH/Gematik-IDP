/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
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
