package de.bdr.servko.keycloak.gematik.idp.mapper

import de.bdr.servko.keycloak.gematik.idp.CardType

class SmcbUserAttributeMapper : AbstractGematikIDPUserAttributeMapper() {

    override val cardType: CardType
        get() = CardType.SMCB

    override fun getId(): String = "gematik-idp-smcb-user-mapper"

    override fun getHelpText(): String =
        "Import the claim of the SMCB card, if it exists, into the specified user attribute."

    override fun getDisplayType(): String = "Gematik SMCB Claim Attribute"

}
