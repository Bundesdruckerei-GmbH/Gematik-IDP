/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.model

import java.net.URI

data class GematikIDPStatusResponse (
    var currentStep: String,
    var nextStepUrl: URI?
)
