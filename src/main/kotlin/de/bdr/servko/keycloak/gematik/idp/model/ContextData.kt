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
