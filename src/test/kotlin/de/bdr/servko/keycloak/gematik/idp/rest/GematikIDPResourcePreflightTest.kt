package de.bdr.servko.keycloak.gematik.idp.rest

import de.bdr.servko.keycloak.gematik.idp.GematikIDP
import de.bdr.servko.keycloak.gematik.idp.service.GematikIdpCertificateService
import jakarta.ws.rs.core.Response
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * Unit test for the [GematikIDPResource.preflight] endpoint.
 *
 * The endpoint returns a JSON object containing the configured free‑port range.
 * The test verifies that the response status is OK and that the payload contains
 * the expected `portRangeStart` and `portRangeEnd` values derived from the
 * configuration (`GematikIDPConfig`).
 */
internal class GematikIDPResourcePreflightTest : GematikIDPEndpointBaseTest() {

    @Test
    fun `preflight returns configured port range`() {
        // Arrange: create a minimal certificate service stub required by the HBA resource.
        val certificateService = object : GematikIdpCertificateService(
            realmMock,
            sessionMock,
            config
        ) {
            override fun generateTokenKeyBytes(): ByteArray = ByteArray(0)
            override fun skipAllValidators(): Boolean = true
        }

        // Act: instantiate the concrete HBA resource (which extends GematikIDPResource) and invoke preflight.
        val underTest = GematikIDPHbaResource(
            realmMock,
            callbackMock,
            sessionMock,
            GematikIDP(sessionMock, config),
            config,
            service,
            formsMock,
            certificateService
        )
        val response: Response = underTest.preflight()

        // Assert status
        assertThat(response.statusInfo).isEqualTo(Response.Status.OK)

        // The entity is a Map<String, Int>. Cast safely for assertions.
        @Suppress("UNCHECKED_CAST")
        val entity = response.entity as? Map<String, Int>
        assertThat(entity).isNotNull
        // Default configuration provides range 1..65535 when not explicitly set.
        assertThat(entity!!["authenticatorPortRangeStart"]).isEqualTo(config.getAuthenticatorPortRangeStart())
        assertThat(entity["authenticatorPortRangeEnd"]).isEqualTo(config.getAuthenticatorPortRangeEnd())
    }
}
