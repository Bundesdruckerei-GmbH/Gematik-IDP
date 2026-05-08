/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.mapper

import de.bdr.servko.keycloak.gematik.idp.model.CardType

class HbaConsentAttributeMapper : AbstractGematikAuthenticatorConsentAttributeMapper() {

    override val cardType: CardType
        get() = CardType.HBA

    override fun getId(): String = "gematik-idp-authenticator-hba-consent-attribute-mapper"

    override fun getHelpText(): String =
        "Save client consent for HBA from Authenticator, into the specified user attribute."

    override fun getDisplayType(): String = "Gematik Authenticator HBA Consent Attributes"

}
