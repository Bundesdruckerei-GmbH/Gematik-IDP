/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.mapper

import de.bdr.servko.keycloak.gematik.idp.model.CardType

class SmcbConsentAttributeMapper : AbstractGematikAuthenticatorConsentAttributeMapper() {

    override val cardType: CardType
        get() = CardType.SMCB

    override fun getId(): String = "gematik-idp-authenticator-smcb-consent-attribute-mapper"

    override fun getHelpText(): String =
        "Save client consent for SMCB from Authenticator, into the specified user attribute."

    override fun getDisplayType(): String = "Gematik Authenticator SMCB Consent Attributes"

}
