/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.GematikIDP
import de.bdr.servko.keycloak.gematik.idp.model.*
import de.bdr.servko.keycloak.gematik.idp.service.GematikIDPService
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpCertificateService
import de.bdr.servko.keycloak.gematik.idp.util.ErrorUtils
import de.bdr.servko.keycloak.gematik.idp.util.GematikIDPUtil
import de.bdr.servko.keycloak.gematik.idp.util.GematikIdpLiterals
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.jboss.logging.Logger
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider
import org.keycloak.forms.login.LoginFormsProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.sessions.AuthenticationSessionModel

class GematikIDPSmcbResource(
    override val realm: RealmModel,
    override val callback: UserAuthenticationIdentityProvider.AuthenticationCallback,
    override val session: KeycloakSession,
    override val gematikIDP: GematikIDP,
    override val config: GematikIDPConfig,
    override val service: GematikIDPService,
    override val forms: LoginFormsProvider = session.getProvider(LoginFormsProvider::class.java),
    override val certificateService: GematikIdpCertificateService,
    override val initialStepName: String = GematikIDPStep.REQUESTED_SMCB_DATA.name,
    override val initialCardType: String = AuthenticationFlowType.SMCB.typeName,
    override val startingCardType: String = AuthenticationCardType.SMCB.typeName,
    override val flowLastStep: GematikIDPStep = GematikIDPStep.RECEIVED_SMCB_DATA,
) : GematikIdpCardTypeBasedResource() {
    override val logger: Logger = Logger.getLogger(this::class.java)

    override fun handleHbaResult(authSession: AuthenticationSessionModel, encodedState: String?, code: String, cardType: String) =
        ErrorUtils.saveCardTypeError(authSession, cardType)

    override fun handleSmcbResult(authSession: AuthenticationSessionModel, encodedState: String?, code: String, cardType: String): Response {
        handleClaimsMap(authSession, code, cardType)

        return encodedState?.let { state ->
            val authenticatorNextStepUrl = GematikIDPUtil.getEndpointUri(session, realm, GematikIDPState.fromEncodedState(state), config, GematikIdpLiterals.AUTHENTICATOR_NEXT_STEP)
            Response.seeOther(authenticatorNextStepUrl).build()
        } ?: Response.ok().type(MediaType.APPLICATION_JSON_TYPE).build()
    }

    override fun finalizeLogin(authSession: AuthenticationSessionModel): Response {
        val smcbData = GematikIDPUtil.getCertificateDataFromAuthNote(authSession, GematikIdpLiterals.SMCB_DATA)
            ?: return getIncompleteIdpDataResponse()

        val telematikId = smcbData[ContextData.CONTEXT_SMCB_TELEMATIK_ID.claim.value] as String

        return callback.authenticated(initIdentityContext(
            telematikId = telematikId,
            authSession = authSession,
            smcbData = smcbData
        ))
    }

}
