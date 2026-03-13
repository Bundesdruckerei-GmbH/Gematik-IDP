package de.bdr.servko.keycloak.gematik.idp.validation

import de.bdr.servko.keycloak.gematik.idp.tsl.TslCertificateVerifierProvider
import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderFactory

class GematikIdpCertificateValidatorProviderFactory : ProviderFactory<GematikIdpCertificateValidatorProvider> {

    companion object {
        const val PROVIDER_ID = "gematik-idp-certificate-validator"

        private val CACHE_TTL_MS = System.getenv("GEMATIK_IDP_CERTIFICATE_VALIDATION_CACHE_TTL_MS")?.toLong()
            ?: CertificateValidationCache.DEFAULT_TTL_MS
    }

    private val logger = Logger.getLogger(this::class.java)

    // Singleton cache shared across all sessions
    private val cache = CertificateValidationCache(CACHE_TTL_MS)

    override fun getId(): String = PROVIDER_ID

    override fun create(session: KeycloakSession): GematikIdpCertificateValidatorProvider {
        val tslProvider = session.getProvider(TslCertificateVerifierProvider::class.java)
            ?: throw IllegalStateException("TslCertificateVerifierProvider not available")

        return GematikIdpCertificateValidatorProvider(tslProvider, cache)
    }

    override fun init(config: Config.Scope?) {
        logger.infof("Initializing GematikIdpCertificateValidatorProvider with cache TTL: %s ms", CACHE_TTL_MS)
    }

    override fun postInit(factory: KeycloakSessionFactory?) {
        // nothing to do
    }

    override fun close() {
        cache.invalidateAll()
    }
}
