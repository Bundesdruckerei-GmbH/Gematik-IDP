/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.model

enum class GematikIDPStep {
    REQUESTED_HBA_DATA,
    RECEIVED_HBA_DATA,
    REQUESTED_SMCB_DATA,
    RECEIVED_SMCB_DATA,
    WAITING_FOR_AUTHENTICATOR_RESPONSE,
    ERROR
}
