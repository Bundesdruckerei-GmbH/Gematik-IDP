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
