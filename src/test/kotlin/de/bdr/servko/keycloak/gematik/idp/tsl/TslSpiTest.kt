/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.tsl

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.keycloak.provider.Spi

class TslSpiTest {

    private lateinit var tslSpi: TslSpi

    @BeforeEach
    fun setUp() {
        tslSpi = TslSpi()
    }

    @Test
    fun `isInternal should return true`() {
        assertThat(tslSpi.isInternal()).isTrue()
    }

    @Test
    fun `getName should return tsl-spi`() {
        assertThat(tslSpi.getName()).isEqualTo("tsl-spi")
    }

    @Test
    fun `getProviderClass should return TslProvider class`() {
        assertThat(tslSpi.getProviderClass()).isEqualTo(TslCertificateVerifierProvider::class.java)
    }

    @Test
    fun `getProviderFactoryClass should return TslProviderFactory class`() {
        assertThat(tslSpi.getProviderFactoryClass()).isEqualTo(TslProviderFactory::class.java)
    }

    @Test
    fun `should implement Spi interface`() {
        assertThat(tslSpi).isInstanceOf(Spi::class.java)
    }

    @Test
    fun `all methods should return non-null values`() {
        assertThat(tslSpi.isInternal()).isNotNull()
        assertThat(tslSpi.getName()).isNotNull()
        assertThat(tslSpi.getProviderClass()).isNotNull()
        assertThat(tslSpi.getProviderFactoryClass()).isNotNull()
    }
}
