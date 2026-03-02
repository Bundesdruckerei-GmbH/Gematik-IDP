/*
 * Copyright 2025 Bundesdruckerei GmbH and/or its affiliates
 * and other contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.bdr.servko.keycloak.gematik.idp.tsl

import de.bdr.servko.keycloak.gematik.idp.validation.GematikIdpCertificateValidatorProvider
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType
import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.connections.httpclient.HttpClientProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.Provider
import org.keycloak.provider.ProviderFactory
import org.keycloak.timer.ScheduledTask
import org.keycloak.timer.TimerProvider
import org.keycloak.truststore.TruststoreProvider
import org.w3c.dom.Document
import java.security.cert.X509Certificate

class TslProviderFactory(
    private val tslRepository: TslCertificateRepository = TslCertificateRepository(),
    private val tslDocumentSignatureVerifier: TslDocumentSignatureVerifier = TslDocumentSignatureVerifier(),
    private val tslDocumentParser: TslDocumentParser = TslDocumentParser(),
    private val tslDocumentUnmarshaller: TslDocumentUnmarshaller = TslDocumentUnmarshaller(),
    private val tslDownloadClientFactory: (KeycloakSession) -> TslDownloadClient = { session ->
        TslDownloadClient(
            session
        )
    },
) : ProviderFactory<TslCertificateVerifierProvider> {

    companion object {
        const val ID = "tsl-provider-factory"

        const val TASK_NAME = "GematikIdpTslUpdate"
        private val TIMER_INTERVAL_MS =
            System.getenv("GEMATIK_IDP_TSL_UPDATE_INTERVAL_MS")?.toLong() ?: (6 * 60 * 60 * 1000) // 6 hours
    }

    private val logger = Logger.getLogger(javaClass)

    private var sessionFactory: KeycloakSessionFactory? = null
    private var scheduledTask: ScheduledTask? = null

    override fun getId(): String = ID

    override fun init(config: Config.Scope?) {
        // noop
    }

    override fun postInit(factory: KeycloakSessionFactory) {
        this.sessionFactory = factory
        val session = factory.create()
        updateTSL(session)
        schedulePeriodicUpdate(session)
    }

    override fun dependsOn(): Set<Class<out Provider>> =
        setOf(HttpClientProvider::class.java, TruststoreProvider::class.java)

    override fun close() {
        scheduledTask?.let {
            sessionFactory?.let { factory ->
                val session = factory.create()
                cancelPeriodicTask(session)
            }
        }
    }

    override fun create(session: KeycloakSession): TslCertificateVerifierProvider = createTslProvider(session)

    private fun createTslProvider(session: KeycloakSession): TslCertificateVerifierProvider =
        TslCertificateVerifierProvider(session.getProvider(TruststoreProvider::class.java), tslRepository)

    private fun updateTSL(session: KeycloakSession) {
        logger.info("Starting TSL update")
        val tsl: String = tslDownloadClientFactory(session).fetchTsl() ?: return
        val document: Document = tslDocumentParser.loadDocument(tsl) ?: return
        val trustStatusList: TrustStatusListType = tslDocumentUnmarshaller.unmarshall(document) ?: return
        val tslDocument = TslDocument(trustStatusList)

        val tslSignatureVerificationResult =
            verifyTslSigningCertificate(tslDocument, session)
                .let { signingCertResult ->
                    signingCertResult.takeUnless { it.isValid && it.certificate != null }
                        ?: verifyTslSignatureWithSigningCertificate(document, signingCertResult.certificate!!)
                }

        if (tslSignatureVerificationResult.isValid) {
            logger.info("TSL document has valid signature")
            val tslData = tslDocument.getPrincipalToCertificateMap()
            val previousSequenceNumber = tslRepository.getSequenceNumber()

            if (tslDocument.getTslSequenceNumber() > previousSequenceNumber.get()) {
                invalidateCertificateValidationCache(session)
            }
            tslRepository.updateDataFromTsl(session, tslData, tslDocument.getTslSequenceNumber())
        } else {
            logger.warn("TSL document has no valid signature: '${tslSignatureVerificationResult.errorMessage}'")
        }
    }

    private fun verifyTslSigningCertificate(
        tslDocument: TslDocument,
        session: KeycloakSession,
    ): CertificateVerificationResult =
        tslDocument.getTslSigningCertificate()?.let { signingCertificate ->
            createTslProvider(session).verifyTslSigningCertificateWithTemporaryTslData(
                signingCertificate,
                tslRepository.createCertificateMap(session, tslDocument.getPrincipalToCertificateMap())
            )
        } ?: CertificateVerificationResult(false, errorMessage = "No signing certificate found in TSL document")

    private fun verifyTslSignatureWithSigningCertificate(
        document: Document,
        signingCertificate: X509Certificate,
    ): CertificateVerificationResult = tslDocumentSignatureVerifier.validateTslSignature(document, signingCertificate)

    private fun schedulePeriodicUpdate(session: KeycloakSession) {
        try {
            val timerProvider = session.getProvider(TimerProvider::class.java)
            scheduledTask = ScheduledTask { session -> updateTSL(session) }
            timerProvider.scheduleTask(scheduledTask, TIMER_INTERVAL_MS, TASK_NAME)
            logger.info("Scheduled periodic TSL update task $TASK_NAME")
        } catch (e: Exception) {
            logger.error("Failed to schedule periodic TSL update task $TASK_NAME", e)
            scheduledTask = null
        } finally {
            session.close()
        }
    }

    private fun cancelPeriodicTask(session: KeycloakSession) {
        try {
            val timerProvider = session.getProvider(TimerProvider::class.java)
            timerProvider.cancelTask(TASK_NAME)
            logger.info("Cancelled scheduled TSL update task $TASK_NAME")
        } catch (e: Exception) {
            logger.error("Error cancelling scheduled TSL task $TASK_NAME", e)
        } finally {
            session.close()
        }
    }

    private fun invalidateCertificateValidationCache(session: KeycloakSession) {
        try {
            val provider = session.getProvider(GematikIdpCertificateValidatorProvider::class.java)
            provider?.invalidateCache()
            logger.info("Certificate validation cache invalidated due to TSL update")
        } catch (e: Exception) {
            logger.warn("Failed to invalidate certificate validation cache: ${e.message}")
        }
    }
}
