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
import org.keycloak.http.simple.SimpleHttp
import org.keycloak.http.simple.SimpleHttpRequest
import org.keycloak.http.simple.SimpleHttpResponse
import org.keycloak.models.KeycloakSession
import org.mockito.Mockito.mockStatic
import org.mockito.kotlin.*
import java.io.IOException

class TslDownloadClientTest {

    private val session = mock<KeycloakSession>()

    val response = mock<SimpleHttpResponse> {
        on { status } doReturn 200
        on { asString() } doReturn ""
    }
    val mockHttpRequest = mock<SimpleHttpRequest> {
        on { header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_XML) } doReturn this.mock
        on { asResponse() } doReturn response
    }
    val mockSimpleHttp = mock<SimpleHttp> {
        on { doGet(eq("tslUrl")) } doReturn mockHttpRequest
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
                SimpleHttp.create(session)
            }.thenReturn(mockSimpleHttp)

            val tslDownloadClient = TslDownloadClient(session, "tslUrl", null)
            val result = tslDownloadClient.fetchTsl()

            // assert
            assertThat(result).isNotNull
        }
    }

    @Test
    fun `fetchTsl - with fallback url - success`() {
        val fallbackResponse = mock<SimpleHttpResponse> {
            on { status } doReturn 200
            on { asString() } doReturn ""
        }
        val fallbackRequest = mock<SimpleHttpRequest> {
            on { header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_XML) } doReturn this.mock
            on { asResponse() } doReturn fallbackResponse
        }
        val fallbackSimpleHttp = mock<SimpleHttp> {
            on { doGet(eq("tslBackupUrl")) } doReturn fallbackRequest
        }
        mockStatic(SimpleHttp::class.java).use { mockedStatic ->
            mockedStatic.`when`<Any> {
                SimpleHttp.create(session)
            }
                .thenReturn(mockSimpleHttp) // first call → primary
                .thenReturn(fallbackSimpleHttp)  // second call → fallback
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
                SimpleHttp.create(session)
            }.thenReturn(mockSimpleHttp)
            whenever(response.status) doReturn 500

            val tslDownloadClient = TslDownloadClient(session, "tslUrl", null)
            val result = tslDownloadClient.fetchTsl()

            // assert
            assertThat(result).isNull()
        }
    }

    @Test
    fun `fetchTsl - IOException - failure`() {
        mockStatic(SimpleHttp::class.java).use { mockedStatic ->
            mockedStatic.`when`<Any> {
                SimpleHttp.create(session)
            }.thenReturn(mockSimpleHttp)
            whenever(mockHttpRequest.asResponse()) doThrow IOException()

            val tslDownloadClient = TslDownloadClient(session, "tslUrl", null)

            val result = tslDownloadClient.fetchTsl()

            // assert
            assertThat(result).isNull()
        }
    }

}
