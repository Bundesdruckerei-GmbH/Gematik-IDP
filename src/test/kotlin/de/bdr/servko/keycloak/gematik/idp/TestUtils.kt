package de.bdr.servko.keycloak.gematik.idp

import de.bdr.servko.keycloak.gematik.idp.token.TestTokenUtil
import org.keycloak.util.JsonSerialization

object TestUtils {

    //keep it host.docker.internal, since the mock tokens are copied from it
    val discoveryDocument = GematikDiscoveryDocument(
        issuer = "https://idp.zentral.idp.splitdns.ti-dienste.de",
        authorizationEndpoint = "http://host.docker.internal:8081/sign_response",
        tokenEndpoint = "http://host.docker.internal:8081/token",
        jwksUri = "http://host.docker.internal:8081/jwks",
        pukEncUri = "http://host.docker.internal:8081/idpEnc/jwk.json",
        pukSigUri = "http://host.docker.internal:8081/idpSig/jwk.json",
        expiration = 1667981784000
    )

    fun getJsonHbaToken(): String {
        val idToken = TestTokenUtil.buildHbaIdToken()
        val accessToken = TestTokenUtil.buildHbaAccessToken()

        return buildTokenAsJson(idToken, accessToken)
    }

    fun getJsonSmcbToken(): String {
        val idToken = TestTokenUtil.buildSmcbIdToken()
        val accessToken = TestTokenUtil.buildSmcbAccessToken()
        return buildTokenAsJson(idToken, accessToken)
    }

    private fun buildTokenAsJson(idToken: String, accessToken: String): String {
        val token = Token(id_token = idToken, access_token = accessToken)
        return JsonSerialization.writeValueAsString(token)
    }

    data class Token(
        val expires_in: Int = 300,
        val token_type: String = "Bearer",
        val id_token: String,
        val access_token: String,
    )
}
