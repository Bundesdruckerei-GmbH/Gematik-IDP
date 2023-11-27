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

import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPStep
import jakarta.ws.rs.core.Response
import org.keycloak.sessions.AuthenticationSessionModel

class ErrorUtils {
    companion object {
        fun saveIdpErrorInAuthSession(
            authSession: AuthenticationSessionModel,
            error: String?,
            errorDetails: String?,
            errorUri: String?,
        ): Response {
            authSession.setAuthNote(GematikIdpLiterals.ERROR, error)
            authSession.setAuthNote(GematikIdpLiterals.ERROR_DETAILS, errorDetails)
            authSession.setAuthNote(GematikIdpLiterals.ERROR_URI, errorUri)
            authSession.setAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP, GematikIDPStep.ERROR.name)

            return Response.noContent().build()
        }

        fun saveCardTypeError(
            authSession: AuthenticationSessionModel,
            cardType: String,
        ): Response {
            authSession.setAuthNote(GematikIdpLiterals.ERROR, "unsupported_card_type")
            authSession.setAuthNote(
                GematikIdpLiterals.ERROR_DETAILS,
                "Received ${cardType.uppercase()} data, which is not configured for this flow."
            )
            authSession.setAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP, GematikIDPStep.ERROR.name)
            authSession.setAuthNote(GematikIdpLiterals.ERROR_URI, null)

            return Response.noContent().build()
        }

        fun saveUnsupportedAuthenticatorVersion(authSession: AuthenticationSessionModel): Response {
            authSession.setAuthNote(GematikIdpLiterals.ERROR, "unsupported_authenticator_version")
            authSession.setAuthNote(
                GematikIdpLiterals.ERROR_DETAILS,
                "Authenticator version unsupported. Please update your Authenticator."
            )
            authSession.setAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP, GematikIDPStep.ERROR.name)
            authSession.setAuthNote(GematikIdpLiterals.ERROR_URI, null)

            return Response.noContent().build()
        }
    }
}
