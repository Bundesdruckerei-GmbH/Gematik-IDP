/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.model

enum class AuthenticationFlowType(var typeName: String) {
    MULTI("multi"),
    HBA("HBA"),
    SMCB("SMC-B");
}
