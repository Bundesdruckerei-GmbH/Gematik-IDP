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

package de.bdr.servko.keycloak.gematik.idp

import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.keycloak.models.IdentityProviderModel

internal class GematikIDPConfigTest {

    @Test
    fun setTimeoutMs() {
        val timeout = "100000"
        val idpConfig = GematikIDPConfig()
        idpConfig.setTimeoutMs(timeout)

        Assertions.assertThat(idpConfig.config["timeoutMs"]).isEqualTo(timeout)
    }

    @Test
    fun getTimeoutMs() {
        val config= LinkedHashMap<String, String>()
        val timeout = 100000
        config["timeoutMs"] = timeout.toString()
        val model = IdentityProviderModel()
        model.config = config

        val idpConfig = GematikIDPConfig(model)

        Assertions.assertThat(idpConfig.getTimeoutMs()).isEqualTo(timeout)
    }

    @Test
    fun setIdpTimeoutMs() {
        val idpTimeout = "100000"
        val idpConfig = GematikIDPConfig()
        idpConfig.setIdpTimeoutMs(idpTimeout)

        Assertions.assertThat(idpConfig.config["idpTimeoutMs"]).isEqualTo(idpTimeout)
    }

    @Test
    fun getIdpTimeoutMs() {
        val config= LinkedHashMap<String, String>()
        val idpTimeout = 100000
        config["idpTimeoutMs"] = idpTimeout.toString()
        val model = IdentityProviderModel()
        model.config = config

        val idpConfig = GematikIDPConfig(model)

        Assertions.assertThat(idpConfig.getIdpTimeoutMs()).isEqualTo(idpTimeout)
    }
}
