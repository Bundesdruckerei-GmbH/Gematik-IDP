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

package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpOpenIDConfigurationService
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator
import javax.ws.rs.GET
import javax.ws.rs.Path
import javax.ws.rs.Produces
import javax.ws.rs.QueryParam
import javax.ws.rs.core.MediaType
import javax.ws.rs.core.Response

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
    fun openidConfiguration(@QueryParam("url") url: String, @QueryParam("user-agent") userAgent: String): Response {
        // note: fine-grained admin permissions (see UsersResource#createUser) not supported for this endpoint
        auth.realm().requireManageIdentityProviders()
        return Response.ok()
            .entity(service.getOpenIDConfiguration(url, userAgent).claimsMap)
            .build()
    }
}
