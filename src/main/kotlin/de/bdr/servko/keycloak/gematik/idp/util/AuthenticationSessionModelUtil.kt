/*
 * Copyright 2026 Bundesdruckerei GmbH and/or its affiliates
 * and other contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.bdr.servko.keycloak.gematik.idp.util

import org.keycloak.sessions.AuthenticationSessionModel

fun AuthenticationSessionModel.getHandshakeIdAuthNote(): String? =
    this.getAuthNote(GematikIdpLiterals.HANDSHAKE_ID)

fun AuthenticationSessionModel.getAuthenticatorPortAuthNote(): Int? =
    this.getAuthNote(GematikIdpLiterals.AUTHENTICATOR_PORT)?.toIntOrNull()

fun AuthenticationSessionModel.getCodeVerifierAuthNote(): String? =
    this.getAuthNote(GematikIdpLiterals.CODE_VERIFIER)

fun AuthenticationSessionModel.setCodeVerifierAuthNote(codeVerifier: String) =
    this.setAuthNote(GematikIdpLiterals.CODE_VERIFIER, codeVerifier)

fun AuthenticationSessionModel.getAuthenticatorVersionAuthNote(): String? =
    this.getAuthNote(GematikIdpLiterals.AUTHENTICATOR_VERSION)

fun AuthenticationSessionModel.setAuthenticatorVersionAuthNote(version: String) =
    this.setAuthNote(GematikIdpLiterals.AUTHENTICATOR_VERSION, version)

fun AuthenticationSessionModel.setGematikIDPStepAuthNote(idpStep: String) =
    this.setAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP, idpStep)

fun AuthenticationSessionModel.getGematikIDPStepAuthNote(): String? =
    this.getAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP)

fun AuthenticationSessionModel.getLoginStartTimeAuthNote(): String? =
    this.getAuthNote(GematikIdpLiterals.LOGIN_START_TIME_NOTE)
