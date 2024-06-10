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

class GematikIdpLiterals {
    companion object {
        const val START_AUTH_PATH = "startAuth"
        const val RESULT_PATH = "result"
        const val TIMEOUT_PATH = "timeout"
        const val AUTHENTICATION_STATUS = "status"
        const val AUTHENTICATOR_NEXT_STEP = "nextStep"
        const val AUTHENTICATOR_VERSION = "authenticatorVersion"

        const val CHALLENGE_PATH = "challenge_path"
        const val CALLBACK = "callback"
        const val CARD_TYPE = "cardType"

        const val SCOPE_HBA = "Person_ID"
        const val SCOPE_SMCB = "Institutions_ID"
        const val TOKEN_KEY = "token_key"
        const val KEY_VERIFIER = "key_verifier"

        const val CODE_VERIFIER = "CODE_VERIFIER"
        const val GEMATIK_IDP_STEP = "GEMATIK_IDP_STEP"
        const val HBA_DATA = "HBA_DATA"
        const val SMCB_DATA = "SMCB_DATA"

        const val ERROR = "error"
        const val ERROR_DETAILS = "error_details"
        const val ERROR_URI = "error_uri"

        const val CONSENT_DECLINED_ERROR = "access_denied"
        const val CONSENT_DECLINED_ERROR_DETAIL = "User declined consent"
    }
}
