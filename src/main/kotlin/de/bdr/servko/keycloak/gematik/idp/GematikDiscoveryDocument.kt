package de.bdr.servko.keycloak.gematik.idp

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
