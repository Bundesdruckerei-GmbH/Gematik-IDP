/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.validation

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class GematikIdpCertificateValidatorSpiTest {

    private val underTest = GematikIdpCertificateValidatorSpi()

    @Test
    fun `getName should return correct name`() {
        assertThat(underTest.name).isEqualTo(GematikIdpCertificateValidatorSpi.NAME)
    }

    @Test
    fun `isInternal should return false`() {
        assertThat(underTest.isInternal).isFalse()
    }

    @Test
    fun `getProviderClass should return GematikIdpCertificateValidatorProvider`() {
        assertThat(underTest.providerClass).isEqualTo(GematikIdpCertificateValidatorProvider::class.java)
    }

    @Test
    fun `getProviderFactoryClass should return GematikIdpCertificateValidatorProviderFactory`() {
        assertThat(underTest.providerFactoryClass).isEqualTo(GematikIdpCertificateValidatorProviderFactory::class.java)
    }
}
