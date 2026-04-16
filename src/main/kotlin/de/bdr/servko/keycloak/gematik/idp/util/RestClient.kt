/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.util

import com.fasterxml.jackson.databind.JsonNode
import de.bdr.servko.keycloak.gematik.idp.exception.IdpUnavailableException
import jakarta.ws.rs.core.HttpHeaders
import org.jboss.logging.Logger
import org.keycloak.broker.provider.util.SimpleHttp
import org.keycloak.models.KeycloakSession

open class RestClient(private val session: KeycloakSession) {
    private val logger = Logger.getLogger(this::class.java)

    open fun doGet(idpUrl: String, userAgent: String): String {
        val response = SimpleHttp.doGet(idpUrl, session).header(HttpHeaders.USER_AGENT, userAgent).asResponse().also {
            handleErrorResponse(it, idpUrl, "GET")
        }

        return response.asString()
    }

    open fun doPost(
        idpUrl: String,
        paramMap: Map<String, String> = emptyMap(),
        timoutMs: Int,
        userAgent: String,
    ): JsonNode =
        SimpleHttp.doPost(idpUrl, session)
            .connectTimeoutMillis(timoutMs)
            .connectionRequestTimeoutMillis(timoutMs)
            .socketTimeOutMillis(timoutMs).header(HttpHeaders.USER_AGENT, userAgent).apply {
                paramMap.map { param(it.key, it.value) }
            }.asResponse().also {
                handleErrorResponse(it, idpUrl, "POST")
            }.asJson()

    private fun handleErrorResponse(response: SimpleHttp.Response, idpUrl: String, method: String) {
        if (response.status >= 500) {
            logger.warn("IDP $idpUrl returned status code ${response.status} with body ${response.asString()}")
            throw IdpUnavailableException("IDP $idpUrl returned status code ${response.status} with body ${response.asString()}")
        } else if (response.status >= 400) {
            logger.warn("IDP $idpUrl returned status code ${response.status} with body ${response.asString()}")
        } else {
            logger.info("$method $idpUrl response ${response.status}")
        }
    }
}
