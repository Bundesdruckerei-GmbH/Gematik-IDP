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

import org.jose4j.jws.EcdsaUsingShaAlgorithm
import org.jose4j.jws.JsonWebSignatureAlgorithm
import org.keycloak.crypto.JavaAlgorithm

open class BrainpoolAlgorithmSuites(
    id: String, javaAlgo: String, curveName: String, signatureByteLength: Int
) : EcdsaUsingShaAlgorithm(id, javaAlgo, curveName, signatureByteLength), JsonWebSignatureAlgorithm {
    class EcdsaBP256R1UsingSha256 : BrainpoolAlgorithmSuites(
        "BP256R1", JavaAlgorithm.ES256, BrainpoolCurves.BP_256, 64
    )

    class EcdsaBP384R1UsingSha384 : BrainpoolAlgorithmSuites(
        "BP384R1", JavaAlgorithm.ES384, BrainpoolCurves.BP_384, 96
    )

    class EcdsaBP512R1UsingSha512 : BrainpoolAlgorithmSuites(
        "BP512R1", JavaAlgorithm.ES512, BrainpoolCurves.BP_512, 132
    )
}
