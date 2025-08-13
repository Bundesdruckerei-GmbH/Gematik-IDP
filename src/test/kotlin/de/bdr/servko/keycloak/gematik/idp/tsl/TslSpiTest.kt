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
