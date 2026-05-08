/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
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
