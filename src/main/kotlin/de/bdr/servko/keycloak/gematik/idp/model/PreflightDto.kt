/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.model

/**
 * DTO that represents the “pre‑flight” information that the client
 * needs in order to talk to the authenticator.
 *
 * @property authenticatorPortRangeStart  inclusive start of the allowed port range
 * @property authenticatorPortRangeEnd    inclusive end of the allowed port range
 */
data class PreflightDto(
    val authenticatorPortRangeStart: Int,
    val authenticatorPortRangeEnd: Int
)
