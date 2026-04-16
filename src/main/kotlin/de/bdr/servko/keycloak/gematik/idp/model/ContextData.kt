/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.model

import org.keycloak.representations.IDToken

enum class CardType { HBA, SMCB }

enum class GematikClaim(val value: String) {
    TELEMATIK_ID("idNummer"),
    PROFESSION_OID("professionOID"),
    FAMILY_NAME(IDToken.FAMILY_NAME),
    GIVEN_NAME(IDToken.GIVEN_NAME),
    ORGANIZATION_NAME("organizationName")
}

enum class AuthenticatorClaim(val cardType: CardType, val scope: String) {
    HBA_CONSENT_CREATED_DATE(CardType.HBA, "hba_consent_created_date"),
    HBA_CONSENT_LAST_UPDATED_DATE(CardType.HBA, "hba_consent_last_updated_date"),
    SMCB_CONSENT_CREATED_DATE(CardType.SMCB, "smcb_consent_created_date"),
    SMCB_CONSENT_LAST_UPDATED_DATE(CardType.SMCB, "smcb_consent_last_updated_date")
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
