package de.bdr.servko.keycloak.gematik.idp.mapper

import de.bdr.servko.keycloak.gematik.idp.CardType

class HbaUserAttributeMapper : AbstractGematikIDPUserAttributeMapper() {

    override val cardType: CardType
        get() = CardType.HBA

    override fun getId(): String = "gematik-idp-hba-user-mapper"

    override fun getHelpText(): String =
        "Import the claim of the HBA card, if it exists, into the specified user attribute."

    override fun getDisplayType(): String = "Gematik HBA Claim Attribute"

}
