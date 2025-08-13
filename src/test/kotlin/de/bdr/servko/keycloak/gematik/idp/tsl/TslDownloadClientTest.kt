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

import jakarta.ws.rs.core.MediaType
import org.apache.http.HttpHeaders
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.NullAndEmptySource
import org.keycloak.broker.provider.util.SimpleHttp
import org.keycloak.models.KeycloakSession
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.mockStatic
import org.mockito.kotlin.*
import java.io.IOException

class TslDownloadClientTest {

    private val session = mock<KeycloakSession>()

    val response = mock<SimpleHttp.Response> {
        on { status } doReturn 200
        on { asString() } doReturn ""
    }
    val mockHttp = mock<SimpleHttp> {
        on { header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_XML) } doReturn this.mock
        on { asResponse() } doReturn response
    }

    @ParameterizedTest
    @NullAndEmptySource
    fun `fetchTsl - no urls defined`(urls: String?) {
        // act
        val result = TslDownloadClient(session, urls, urls).fetchTsl()

        // assert
        assertThat(result).isNull()
    }

    @Test
    fun `fetchTsl - with primary url - success`() {
        mockStatic(SimpleHttp::class.java).use { mockedStatic ->
            mockedStatic.`when`<Any> {
                SimpleHttp.doGet(eq("tslUrl"), any())
            }.thenReturn(mockHttp)

            val tslDownloadClient = TslDownloadClient(session, "tslUrl", null)
            val result = tslDownloadClient.fetchTsl()

            // assert
            assertThat(result).isNotNull
        }
    }

    @Test
    fun `fetchTsl - with fallback url - success`() {
        val response2 = mock<SimpleHttp.Response> {
            on { status } doReturn 200
            on { asString() } doReturn ""
        }
        val mockHttp2 = mock<SimpleHttp> {
            on { header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_XML) } doReturn this.mock
            on { asResponse() } doReturn response2
        }

        mockStatic(SimpleHttp::class.java).use { mockedStatic ->
            mockedStatic.`when`<Any> {
                SimpleHttp.doGet(anyString(), any())
            }.thenReturn(mockHttp)
                .thenReturn(mockHttp2)
            whenever(response.status) doReturn 503


            val tslDownloadClient = TslDownloadClient(session, "tslUrl", "tslBackupUrl")
            val result = tslDownloadClient.fetchTsl()

            // assert
            assertThat(result).isNotNull
        }
    }

    @Test
    fun `fetchTsl - response not ok - failure`() {
        mockStatic(SimpleHttp::class.java).use { mockedStatic ->
            mockedStatic.`when`<Any> {
                SimpleHttp.doGet(anyString(), any())
            }.thenReturn(mockHttp)
            whenever(response.status) doReturn 500

            val tslDownloadClient = TslDownloadClient(session, "tslUrl", "tslBackupUrl")
            val result = tslDownloadClient.fetchTsl()

            // assert
            assertThat(result).isNull()
        }
    }

    @Test
    fun `fetchTsl - IOException - failure`() {
        mockStatic(SimpleHttp::class.java).use { mockedStatic ->
            mockedStatic.`when`<Any> {
                SimpleHttp.doGet(anyString(), any())
            }.thenReturn(mockHttp)
            whenever(mockHttp.asResponse()) doThrow IOException()

            val tslDownloadClient = TslDownloadClient(session, "tslUrl", "tslBackupUrl")

            val result = tslDownloadClient.fetchTsl()

            // assert
            assertThat(result).isNull()
        }
    }

}
