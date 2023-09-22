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

import de.bdr.servko.keycloak.gematik.idp.util.VersionFromUserAgentReader
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.EmptySource
import org.junit.jupiter.params.provider.ValueSource

internal class AuthenticatorVersionTest {
    @ParameterizedTest
    @CsvSource(
        "'3.1.0','3.1.0'",
        "'13.11.10','13.11.10'",
        "'4.4.0 3.1.0','4.4.0'",
        "'4.4.0-alpha','4.4.0-alpha'",
        "'4.4.0-alpha+20130313144700','4.4.0-alpha+20130313144700'",
    )
    fun `from with version string containing version - version is parsed and returned`(
        userAgent: String,
        version: String,
    ) {
        // arrange + act
        val result = AuthenticatorVersion.from(userAgent)

        // assert
        assertThat(result.toString()).isEqualTo(version)
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = [
        "dev",
        "13.0.A",
        "13.0A.0A",
        "13.0",
    ])
    fun `from with version string containing not parseable version - version is parsed and returned`(userAgent: String) {
        // arrange + act
        val result = VersionFromUserAgentReader.readVersionFrom(userAgent)

        // assert
        assertThat(result.toString()).isEqualTo("unknown")
    }

    @ParameterizedTest
    @CsvSource(
        ",,",
        "2,,",
        ",2,",
        ",,2",
        "2,2,",
        ",2,2",
        "2,,2",
    )
    fun `isNullOrEmpty with empty major string - returns true`(
        major: Int?,
        minor: Int?,
        patch: Int?,
    ) {
        // arrange + act
        val result = AuthenticatorVersion(major, minor, patch).isNullOrEmpty()

        // assert
        assertThat(result).isTrue
    }

    @Test
    fun `isNullOrEmpty with a non empty major string - return false`() {
        // arrange + act
        val result = AuthenticatorVersion(2, 2, 2).isNullOrEmpty()

        // assert
        assertThat(result).isFalse
    }

    @Test
    fun `isGreaterThenOrEqual with empty versions - true`() {
        // arrange
        val source = AuthenticatorVersion()
        val toCompare = AuthenticatorVersion()

        // act
        val result = source.isGreaterThenOrEqual(toCompare)

        // assert
        assertThat(result).isTrue
    }

    @ParameterizedTest
    @CsvSource(
        "2,2,2",
        "1,2,2",
        "1,1,2",
        "1,2,1",
    )
    fun `isGreaterThenOrEqual with greater version to compare - false`(
        major: Int?,
        minor: Int?,
        patch: Int?
    ) {
        // arrange
        val source = AuthenticatorVersion(1, 1, 1)
        val toCompare = AuthenticatorVersion(major , minor, patch)

        // act
        val result = source.isGreaterThenOrEqual(toCompare)

        // assert
        assertThat(result).isFalse
    }

    @ParameterizedTest
    @CsvSource(
        ",,",
        "2,2,2",
        "1,1,1",
        "2,1,1",
        "2,1,2",
        "2,2,1",
    )
    fun `isGreaterThenOrEqual with smaller version to compare - is true`(
        major: Int?,
        minor: Int?,
        patch: Int?
    ) {
        // arrange
        val source = AuthenticatorVersion(2, 2, 2)
        val toCompare = AuthenticatorVersion(major , minor, patch)

        // act
        val result = source.isGreaterThenOrEqual(toCompare)

        // assert
        assertThat(result).isTrue
    }
}
