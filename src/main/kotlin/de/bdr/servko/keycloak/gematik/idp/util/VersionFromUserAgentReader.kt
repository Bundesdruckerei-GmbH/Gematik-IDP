/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.util

import de.bdr.servko.keycloak.gematik.idp.model.AuthenticatorVersion

class VersionFromUserAgentReader {
    companion object {
        fun readVersionFrom(userAgent: String?): AuthenticatorVersion {
            if (userAgent.isNullOrEmpty() || !userAgent.startsWith("authenticator/")) {
                return AuthenticatorVersion()
            }
            return AuthenticatorVersion.from(userAgent)
        }
    }
}
