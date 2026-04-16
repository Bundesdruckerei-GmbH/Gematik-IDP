/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.tsl

import jakarta.ws.rs.core.MediaType
import org.apache.http.HttpHeaders
import org.jboss.logging.Logger
import org.keycloak.broker.provider.util.SimpleHttp
import org.keycloak.models.KeycloakSession
import java.io.IOException

/**
 * Client to download TSL XML.
 *
 * See https://gemspec.gematik.de/docs/gemSpec/gemSpec_TSL/gemSpec_TSL_V1.23.0/#A_17680-01
 * for available primary and secondary urls.
 */
class TslDownloadClient(
    private val session: KeycloakSession,
    private val tslUrl: String? = System.getenv("GEMATIK_IDP_TSL_PRIMARY_URL"),
    private val tslBackupUrl: String? = System.getenv("GEMATIK_IDP_TSL_SECONDARY_URL"),
) {

    private val logger: Logger = Logger.getLogger(javaClass)

    /**
     * Fetch the TSL document from the environment variable "GEMATIK_IDP_TSL_PRIMARY_URL" or "GEMATIK_IDP_TSL_SECONDARY_URL".
     *
     * If no result was fetched from the primary url, the secondary url is used.
     *
     * @return TSL xml string or {@code null} if no url was defined or an error occurred
     */
    fun fetchTsl(): String? =
        if (tslUrl.isNullOrBlank() && tslBackupUrl.isNullOrBlank()) {
            logger.warn("Tsl URLs not set, define environment variables \"GEMATIK_IDP_TSL_PRIMARY_URL\" and \"GEMATIK_IDP_TSL_SECONDARY_URL\"")
            null
        } else {
            fetchTsl(tslUrl) ?: fetchTsl(tslBackupUrl)
        }

    private fun fetchTsl(url: String?): String? =
        url?.takeIf { it.isNotBlank() }
            ?.let { downloadTsl(it) }

    private fun downloadTsl(url: String): String? =
        try {
            val response = SimpleHttp
                .doGet(url, session)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_XML)
                .asResponse()
            if (response.status == 200) {
                response.asString()
            } else {
                logger.warn("Failed to fetch TSL from $url, status ${response.status}")
                null
            }
        } catch (e: IOException) {
            logger.warn("Failed to fetch TSL from $url", e)
            null
        }
}
