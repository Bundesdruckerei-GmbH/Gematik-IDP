/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
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
