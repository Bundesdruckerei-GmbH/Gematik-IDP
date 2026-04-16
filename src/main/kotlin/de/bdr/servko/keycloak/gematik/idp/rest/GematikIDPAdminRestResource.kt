/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpOpenIDConfigurationService
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator

class GematikIDPAdminRestResource(
    private val auth: AdminPermissionEvaluator,
    private val service: GematikIdpOpenIDConfigurationService,
) {
    companion object {
        const val OPENID_CONFIGURATION_PATH = "/openid-configuration"
    }

    /**
     * Fetch the openid-configuration and extract the data from the JWT
     */
    @GET
    @Path(OPENID_CONFIGURATION_PATH)
    @Produces(MediaType.APPLICATION_JSON)
    fun openidConfiguration(
        @QueryParam("url") url: String,
        @QueryParam("user-agent") userAgent: String,
        @QueryParam("validateSigningCertificate") validateSigningCertificate: Boolean?,
    ): Response {
        // note: fine-grained admin permissions (see UsersResource#createUser) not supported for this endpoint
        auth.realm().requireManageIdentityProviders()
        return Response.ok()
            .entity(service.getOpenIDConfiguration(url, userAgent, validateSigningCertificate ?: false).claimsMap)
            .build()
    }
}
