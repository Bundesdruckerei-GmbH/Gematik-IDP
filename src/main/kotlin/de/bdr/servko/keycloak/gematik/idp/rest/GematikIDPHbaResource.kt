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

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.GematikIDP
import de.bdr.servko.keycloak.gematik.idp.model.AuthenticationFlowType
import de.bdr.servko.keycloak.gematik.idp.model.ContextData
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPStep
import de.bdr.servko.keycloak.gematik.idp.service.GematikIDPService
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpCertificateService
import de.bdr.servko.keycloak.gematik.idp.util.ErrorUtils
import de.bdr.servko.keycloak.gematik.idp.util.GematikIDPUtil
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals
import org.jboss.logging.Logger
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.util.JsonSerialization
import javax.ws.rs.core.MediaType
import javax.ws.rs.core.Response

class GematikIDPHbaResource(
    override val realm: RealmModel,
    override val callback: IdentityProvider.AuthenticationCallback,
    override val session: KeycloakSession,
    override val gematikIDP: GematikIDP,
    override val config: GematikIDPConfig,
    override val service: GematikIDPService,
    override val forms: LoginFormsProvider = session.getProvider(LoginFormsProvider::class.java),
    override val certificateService: GematikIdpCertificateService,
    override val initialStepName: String = GematikIDPStep.REQUESTED_HBA_DATA.name,
    override val initialCardType: String = AuthenticationFlowType.HBA.typeName,
    override val flowLastStep: GematikIDPStep = GematikIDPStep.RECEIVED_HBA_DATA
) : GematikIdpCardTypeBasedResource() {
    override val logger: Logger = Logger.getLogger(this::class.java)

    override fun handleHbaResult(authSession: AuthenticationSessionModel, code: String, cardType: String): Response {
        val claimsMap = getClaimsMap(authSession, code, cardType)

        authSession.setAuthNote(GematikIdpLiterals.HBA_DATA, JsonSerialization.writeValueAsString(claimsMap))
        authSession.setAuthNote(GematikIdpLiterals.GEMATIK_IDP_STEP, GematikIDPStep.RECEIVED_HBA_DATA.name)

        return Response.ok().type(MediaType.APPLICATION_JSON_TYPE).build()
    }

    override fun handleSmcbResult(authSession: AuthenticationSessionModel, code: String, cardType: String): Response {
        return ErrorUtils.saveCardTypeError(authSession, cardType)
    }

    override fun finalizeLogin(authSession: AuthenticationSessionModel): Response {
        val hbaData = GematikIDPUtil.getCertificateDataFromAuthNote(authSession, GematikIdpLiterals.HBA_DATA)
            ?: return getIncompleteIdpDataResponse()

        val telematikId = hbaData[ContextData.CONTEXT_HBA_TELEMATIK_ID.claim.value] as String

        return callback.authenticated(initIdentityContext(
            telematikId = telematikId,
            authSession = authSession,
            hbaData = hbaData
        ))
    }

}
