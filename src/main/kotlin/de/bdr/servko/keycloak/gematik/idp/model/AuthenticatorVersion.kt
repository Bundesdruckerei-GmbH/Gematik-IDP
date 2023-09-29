/*
 *  Copyright 2023 Bundesdruckerei GmbH and/or its affiliates
 *  and other contributors.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package de.bdr.servko.keycloak.gematik.idp.model

data class AuthenticatorVersion(
    val major: Int? = null,
    val minor: Int? = null,
    val patch: Int? = null,
    val prerelease: String? = null,
    val buildMetadata: String? = null,
) {
    companion object {
        // Originates from: https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
        @Suppress("kotlin:S5843")
        const val VERSION_REGEX =
            """(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?"""

        fun from(versionString: String): AuthenticatorVersion {
            val regex = VERSION_REGEX.toRegex()

            val matchResult = regex.find(versionString)
            val groups = matchResult?.groups
            return if (groups != null && groups.size >= 4) {
                AuthenticatorVersion(
                    major = groups[1]?.value?.toInt(),
                    minor = groups[2]?.value?.toInt(),
                    patch = groups[3]?.value?.toInt(),
                    prerelease = groups[4]?.value,
                    buildMetadata = groups[5]?.value
                )
            } else {
                AuthenticatorVersion()
            }
        }
    }

    override fun toString(): String {
        var result = ""
        if (major != null) result += "$major"
        if (minor != null) result += ".$minor"
        if (patch != null) result += ".$patch"
        if (!prerelease.isNullOrBlank()) result += "-$prerelease"
        if (!buildMetadata.isNullOrBlank()) result += "+$buildMetadata"
        return result.ifEmpty { "unknown" }
    }

    fun isNullOrEmpty(): Boolean {
        return major == null || minor == null || patch == null
    }

    fun isGreaterThenOrEqual(toCompare: AuthenticatorVersion): Boolean {
        return (toCompare.isNullOrEmpty() && !this.isNullOrEmpty()) || (
                (major == toCompare.major || major!! > toCompare.major!!) &&
                        (minor == toCompare.minor || minor!! > toCompare.minor!!) &&
                        (patch == toCompare.patch || patch!! > toCompare.patch!!)
                )
    }
}
