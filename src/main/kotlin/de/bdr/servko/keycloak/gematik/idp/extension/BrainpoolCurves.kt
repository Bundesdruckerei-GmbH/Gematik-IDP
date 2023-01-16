/*
 * Copyright (c) 2022 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.bdr.servko.keycloak.gematik.idp.extension

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.jose4j.jca.ProviderContext
import org.jose4j.jwa.AlgorithmFactoryFactory
import org.jose4j.keys.EllipticCurves
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
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

    private fun addCurve(name: String, spec: ECParameterSpec) {
        try {
            val method: Method =
                EllipticCurves::class.java.getDeclaredMethod(
                    "addCurve",
                    String::class.java,
                    ECParameterSpec::class.java
                )
            method.isAccessible = true
            method.invoke(BrainpoolCurves::class.java, name, spec)
        } catch (e: InvocationTargetException) {
            throw Exception(
                "Error while adding BrainPool-Curves $name to internal Algorithm-Suite repository",
                e
            )
        } catch (e: IllegalAccessException) {
            throw Exception(
                "Error while adding BrainPool-Curves $name to internal Algorithm-Suite repository",
                e
            )
        } catch (e: NoSuchMethodException) {
            throw Exception(
                "Error while adding BrainPool-Curves $name to internal Algorithm-Suite repository",
                e
            )
        }
    }


    fun init() {
        if (initialized) {
            return
        }
        addCurve(BP_256, EC_PARAMETER_SPEC_BP256R1)
        addCurve(BP_384, EC_PARAMETER_SPEC_BP384R1)
        addCurve(BP_512, EC_PARAMETER_SPEC_BP512R1)

        AlgorithmFactoryFactory.getInstance().jwsAlgorithmFactory.apply {
            registerAlgorithm(BrainpoolAlgorithmSuites.EcdsaBP256R1UsingSha256())
            registerAlgorithm(BrainpoolAlgorithmSuites.EcdsaBP384R1UsingSha384())
            registerAlgorithm(BrainpoolAlgorithmSuites.EcdsaBP512R1UsingSha512())
        }
        initialized = true
    }
}
