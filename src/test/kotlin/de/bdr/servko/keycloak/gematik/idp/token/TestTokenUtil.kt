package de.bdr.servko.keycloak.gematik.idp.token

object TestTokenUtil {
    fun jwksMock() = javaClass.classLoader.getResourceAsStream("jwks.json")?.bufferedReader()?.readText() ?: "error"

    fun encJwkMock() = javaClass.classLoader.getResourceAsStream("enc-jwk.json")?.bufferedReader()?.readText() ?: "error"

    fun buildHbaAccessToken() =
        javaClass.classLoader.getResourceAsStream("hba/access_token.txt")?.bufferedReader()?.readText() ?: "error"

    fun buildHbaIdToken() =
        javaClass.classLoader.getResourceAsStream("hba/id_token.txt")?.bufferedReader()?.readText() ?: "error"

    fun buildSmcbAccessToken() =
        javaClass.classLoader.getResourceAsStream("smcb/access_token.txt")?.bufferedReader()?.readText() ?: "error"

    fun buildSmcbIdToken() =
        javaClass.classLoader.getResourceAsStream("smcb/id_token.txt")?.bufferedReader()?.readText() ?: "error"
}
