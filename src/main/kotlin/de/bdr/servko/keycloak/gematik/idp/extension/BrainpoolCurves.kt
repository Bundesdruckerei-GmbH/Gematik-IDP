/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */
package de.bdr.servko.keycloak.gematik.idp.extension

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.jose4j.jca.ProviderContext
import org.jose4j.jwa.AlgorithmFactoryFactory
import org.jose4j.keys.EllipticCurves
import java.security.spec.ECParameterSpec


object BrainpoolCurves {
    const val BP_256 = "BP-256"
    const val BP_384 = "BP-384"
    const val BP_512 = "BP-512"

    private const val BP_256_R1 = "brainpoolP256r1"
    private const val BP_384_R1 = "brainpoolP384r1"
    private const val BP_512_R1 = "brainpoolP512r1"

    private val EC_NAMED_CURVE_PARAMETER_SPEC_BP256R1: ECNamedCurveParameterSpec =
        ECNamedCurveTable.getParameterSpec(BP_256_R1)
    private val EC_NAMED_CURVE_PARAMETER_SPEC_BP384R1: ECNamedCurveParameterSpec =
        ECNamedCurveTable.getParameterSpec(BP_384_R1)
    private val EC_NAMED_CURVE_PARAMETER_SPEC_BP512R1: ECNamedCurveParameterSpec =
        ECNamedCurveTable.getParameterSpec(BP_512_R1)

    private val EC_PARAMETER_SPEC_BP256R1: ECParameterSpec = ECNamedCurveSpec(
        BP_256_R1,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP256R1.curve,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP256R1.g,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP256R1.n,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP256R1.h,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP256R1.seed
    )
    private val EC_PARAMETER_SPEC_BP384R1: ECParameterSpec = ECNamedCurveSpec(
        BP_384_R1,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP384R1.curve,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP384R1.g,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP384R1.n,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP384R1.h,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP384R1.seed
    )
    private val EC_PARAMETER_SPEC_BP512R1: ECParameterSpec = ECNamedCurveSpec(
        BP_512_R1,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP512R1.curve,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP512R1.g,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP512R1.n,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP512R1.h,
        EC_NAMED_CURVE_PARAMETER_SPEC_BP512R1.seed
    )

    val PROVIDER_CONTEXT: ProviderContext = ProviderContext().apply {
        generalProviderContext.generalProvider = BouncyCastleProvider.PROVIDER_NAME
        suppliedKeyProviderContext.generalProvider = BouncyCastleProvider.PROVIDER_NAME
    }

    private var initialized = false

    fun init() {
        if (initialized) {
            return
        }
        EllipticCurves.addCurve(BP_256, EC_PARAMETER_SPEC_BP256R1)
        EllipticCurves.addCurve(BP_384, EC_PARAMETER_SPEC_BP384R1)
        EllipticCurves.addCurve(BP_512, EC_PARAMETER_SPEC_BP512R1)

        AlgorithmFactoryFactory.getInstance().jwsAlgorithmFactory.apply {
            registerAlgorithm(BrainpoolAlgorithmSuites.EcdsaBP256R1UsingSha256())
            registerAlgorithm(BrainpoolAlgorithmSuites.EcdsaBP384R1UsingSha384())
            registerAlgorithm(BrainpoolAlgorithmSuites.EcdsaBP512R1UsingSha512())
        }
        initialized = true
    }
}
