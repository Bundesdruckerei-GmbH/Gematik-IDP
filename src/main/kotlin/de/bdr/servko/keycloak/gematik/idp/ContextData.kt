package de.bdr.servko.keycloak.gematik.idp

import org.keycloak.representations.IDToken

enum class CardType { HBA, SMCB }

enum class GematikClaim(val value: String) {
    TELEMATIK_ID("idNummer"),
    PROFESSION_OID("professionOID"),
    FAMILY_NAME(IDToken.FAMILY_NAME),
    GIVEN_NAME(IDToken.GIVEN_NAME),
    ORGANIZATION_NAME("organizationName")
}

enum class ContextData(val cardType: CardType, val claim: GematikClaim) {
    CONTEXT_HBA_TELEMATIK_ID(CardType.HBA, GematikClaim.TELEMATIK_ID),
    CONTEXT_HBA_PROFESSION_OID(CardType.HBA, GematikClaim.PROFESSION_OID),
    CONTEXT_HBA_FAMILY_NAME(CardType.HBA, GematikClaim.FAMILY_NAME),
    CONTEXT_HBA_GIVEN_NAME(CardType.HBA, GematikClaim.GIVEN_NAME),
    CONTEXT_SMCB_TELEMATIK_ID(CardType.SMCB, GematikClaim.TELEMATIK_ID),
    CONTEXT_SMCB_PROFESSION_OID(CardType.SMCB, GematikClaim.PROFESSION_OID),
    CONTEXT_SMCB_ORGANIZATION_NAME(CardType.SMCB, GematikClaim.ORGANIZATION_NAME),
    CONTEXT_SMCB_FAMILY_NAME(CardType.SMCB, GematikClaim.FAMILY_NAME), //empty on mock
    CONTEXT_SMCB_GIVEN_NAME(CardType.SMCB, GematikClaim.GIVEN_NAME); //empty on mock
}
