/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.tsl

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class TslDocumentParserTest : TslBaseTest() {

    private val underTest = TslDocumentParser()

    @Test
    fun `loadDocument - success`() {
        val (xml, _) = createSignedXml()


        val document = underTest.loadDocument(xml)


        assertThat(document).isNotNull
            .extracting { it?.documentElement?.nodeName }
            .isEqualTo("TrustServiceStatusList")
    }

    @Test
    fun `loadDocument - failure`() {
        val result = underTest.loadDocument("")


        assertThat(result).isNull()
    }

}
