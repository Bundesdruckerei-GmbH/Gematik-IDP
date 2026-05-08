/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.validation

import org.keycloak.provider.Provider
import org.keycloak.provider.ProviderFactory
import org.keycloak.provider.Spi

class GematikIdpCertificateValidatorSpi : Spi {

    companion object {
        const val NAME = "gematik-idp-certificate-validator"
    }

    override fun isInternal(): Boolean = false

    override fun getName(): String = NAME

    override fun getProviderClass(): Class<out Provider> =
        GematikIdpCertificateValidatorProvider::class.java

    override fun getProviderFactoryClass(): Class<out ProviderFactory<out Provider>> =
        GematikIdpCertificateValidatorProviderFactory::class.java
}
