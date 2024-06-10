/*
 *  Copyright 2024 Bundesdruckerei GmbH and/or its affiliates
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

package de.bdr.servko.keycloak.gematik.idp.model

enum class AuthenticatorErrorTypes(var error: String) {
    LOGIN_TIMEOUT("loginTimeout"),
    NON_FINAL_STEP("authenticator.nonFinalStep"),
    INCOMPLETE_IDP_DATA("authenticator.incompleteIdpData"),
    UNSUPPORTED_CARD_TYPE("authenticator.unsupportedCardType"),
    UNSUPPORTED_AUTHENTICATOR_VERSION("authenticator.unsupportedAuthenticatorVersion"),
    CONSENT_DECLINED("authenticator.consentDeclined"),
    ERROR_IDP("authenticator.errorIdp");

    companion object {
        fun valueOf(type: String?): AuthenticatorErrorTypes {
            return when(type) {
                LOGIN_TIMEOUT.error -> LOGIN_TIMEOUT
                NON_FINAL_STEP.error -> NON_FINAL_STEP
                INCOMPLETE_IDP_DATA.error -> INCOMPLETE_IDP_DATA
                UNSUPPORTED_AUTHENTICATOR_VERSION.error -> UNSUPPORTED_AUTHENTICATOR_VERSION
                UNSUPPORTED_CARD_TYPE.error -> UNSUPPORTED_CARD_TYPE
                CONSENT_DECLINED.error -> CONSENT_DECLINED
                else -> ERROR_IDP
            }
        }
    }
}
