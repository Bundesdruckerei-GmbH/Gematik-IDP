/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
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
