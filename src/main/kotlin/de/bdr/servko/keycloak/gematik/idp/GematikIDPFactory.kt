package de.bdr.servko.keycloak.gematik.idp

import de.bdr.servko.keycloak.gematik.idp.extension.BrainpoolCurves
import org.keycloak.broker.provider.AbstractIdentityProviderFactory
import org.keycloak.models.IdentityProviderModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ServerInfoAwareProviderFactory
import java.time.Clock
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.annotation.Generated

class GematikIDPFactory : AbstractIdentityProviderFactory<GematikIDP>(), ServerInfoAwareProviderFactory {
    companion object {
        const val PROVIDER_ID = "gematik-idp"
    }

    private val discoveryDocumentCache = ConcurrentHashMap<String, GematikDiscoveryDocument>()
    override fun getId(): String = PROVIDER_ID
    override fun getName(): String = "Gematik IDP"

    override fun postInit(factory: KeycloakSessionFactory?) {
        BrainpoolCurves.init()
    }

    @Generated
    override fun create(session: KeycloakSession, model: IdentityProviderModel): GematikIDP =
        createAndUpdateConfig(session, GematikIDPConfig(model))

    fun createAndUpdateConfig(
        session: KeycloakSession,
        config: GematikIDPConfig,
        clock: Clock = Clock.systemUTC(),
        serviceFactory: (KeycloakSession) -> GematikIDPService = { GematikIDPService(it) }
    ): GematikIDP {
        val openidConfiguration = discoveryDocumentCache.compute(config.getOpenidConfigUrl()) { url, document ->
            if (document == null || document.expiration < clock.millis()) {
                serviceFactory(session).getOpenIDConfiguration(url, config.getIdpUserAgent())
            } else {
                document
            }
        }
        config.updateOpenidConfig(openidConfiguration!!)
        return GematikIDP(session, config)
    }

    override fun createConfig(): IdentityProviderModel = GematikIDPConfig()
    override fun getOperationalInfo(): Map<String, String> =
        javaClass
            .getResourceAsStream("/META-INF/maven/de.bdr.servko/gematik-idp/pom.properties")
            ?.let {
                val prop = Properties()
                try {
                    prop.load(it)
                } catch (e: Exception) {
                    //ignore
                }
                mapOf("Version" to prop.getProperty("version", "unknown"))
            } ?: mapOf("Version" to "unknown")

}
