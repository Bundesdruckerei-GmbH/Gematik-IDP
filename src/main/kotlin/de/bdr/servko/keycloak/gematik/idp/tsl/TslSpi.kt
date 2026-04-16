/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.tsl

import org.keycloak.provider.Provider
import org.keycloak.provider.ProviderFactory
import org.keycloak.provider.Spi

class TslSpi : Spi {
    override fun isInternal(): Boolean = true

    override fun getName(): String = "tsl-spi"

    override fun getProviderClass(): Class<out Provider> = TslCertificateVerifierProvider::class.java

    override fun getProviderFactoryClass(): Class<out ProviderFactory<*>> = TslProviderFactory::class.java
}
