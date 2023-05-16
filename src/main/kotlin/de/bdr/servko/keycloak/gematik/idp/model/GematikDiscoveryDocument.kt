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

import org.jose4j.jwt.JwtClaims

data class GematikDiscoveryDocument(
    val issuer: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val jwksUri: String,
    val pukEncUri: String,
    val pukSigUri: String,
    val expiration: Long //epoch millis
) {
    constructor(jwtClaims: JwtClaims) : this(
        jwtClaims.getStringClaimValue("issuer"),
        jwtClaims.getStringClaimValue("authorization_endpoint"),
        jwtClaims.getStringClaimValue("token_endpoint"),
        jwtClaims.getStringClaimValue("jwks_uri"),
        jwtClaims.getStringClaimValue("uri_puk_idp_enc"),
        jwtClaims.getStringClaimValue("uri_puk_idp_sig"),
        jwtClaims.expirationTime.valueInMillis
    )
}
