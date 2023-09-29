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

package de.bdr.servko.keycloak.gematik.idp.util

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.NullAndEmptySource
import org.junit.jupiter.params.provider.ValueSource

internal class VersionFromUserAgentReaderTest {

    @ParameterizedTest
    @NullAndEmptySource
    fun `readVersionFrom no user agent given - null returned`(userAgent: String?) {
        // arrange + act
        val result = VersionFromUserAgentReader.readVersionFrom(userAgent)

        // assert
        assertThat(result.major).isNull()
        assertThat(result.minor).isNull()
        assertThat(result.patch).isNull()
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "auth/3.1.0 gematik/!",
        "authenticator/dev gematik/!",
        "authenticator/13.0.A gematik/!",
        "authenticator/13.0 gematik/!",
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 12; moto g pure) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
        "Dalvik/2.1.0 (Linux; U; Android 9; ADT-2 Build/PTT5.181126.002)",
        "Roku4640X/DVP-7.70 (297.70E04154A)"
    ])
    fun `readVersionFrom user agent containing no authenticator version - null returned`(userAgent: String) {
        // arrange + act
        val result = VersionFromUserAgentReader.readVersionFrom(userAgent)

        // assert
        assertThat(result.major).isNull()
        assertThat(result.minor).isNull()
        assertThat(result.patch).isNull()
    }

    @Test
    fun `readVersionFrom user agent containing authenticator version - version is parsed and returned`() {
        // arrange + act
        val userAgent = "authenticator/3.1.0 gematik/!"
        val result = VersionFromUserAgentReader.readVersionFrom(userAgent)

        // assert
        assertThat(result.major).isEqualTo(3)
        assertThat(result.minor).isEqualTo(1)
        assertThat(result.patch).isEqualTo(0)
    }

}
