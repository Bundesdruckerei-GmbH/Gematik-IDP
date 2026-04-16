/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.tsl

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.w3c.dom.Document

class TslDocumentUnmarshallerTest : TslBaseTest() {

    private val underTest = TslDocumentUnmarshaller()

    @Test
    fun `unmarshall - success`() {
        val document = createDocument()


        val result = underTest.unmarshall(document)


        assertThat(result).isNotNull
            .extracting { it?.tslTag }
            .isEqualTo("http://uri.etsi.org/02231/TSLTag")
    }

    @Test
    fun `unmarshall - failure`() {
        val document = mock<Document> {
            on { firstChild } doReturn null
        }


        val result = underTest.unmarshall(document)


        assertThat(result).isNull()
    }

}
