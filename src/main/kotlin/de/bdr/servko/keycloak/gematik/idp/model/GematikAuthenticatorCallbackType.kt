/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.model

enum class GematikAuthenticatorCallbackType {
    OPEN_TAB,
    DIRECT,
    DEEPLINK;

    fun simpleName() = this.name.lowercase()
}
