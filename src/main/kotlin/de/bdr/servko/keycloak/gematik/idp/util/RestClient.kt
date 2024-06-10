/*
 *  Copyright 2023 Bundesdruckerei GmbH and/or its affiliates
 *  and other contributors.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
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
