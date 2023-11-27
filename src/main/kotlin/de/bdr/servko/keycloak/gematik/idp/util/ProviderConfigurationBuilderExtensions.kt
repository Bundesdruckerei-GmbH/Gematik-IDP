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

import de.bdr.servko.keycloak.gematik.idp.model.AuthenticationFlowType
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder


fun ProviderConfigurationBuilder.authenticationFlow(): ProviderConfigurationBuilder = this.property()
    .name("authenticationFlow")
    .label("Choose Authentication Flow")
    .helpText("Choose your preferred authentication flow.")
    .defaultValue(AuthenticationFlowType.MULTI.toString())
    .options(
        listOf(
            AuthenticationFlowType.LEGACY.toString(),
            AuthenticationFlowType.MULTI.toString(),
            AuthenticationFlowType.HBA.toString(),
            AuthenticationFlowType.SMCB.toString()
        )
    )
    .type(ProviderConfigProperty.LIST_TYPE)
    .add()

fun ProviderConfigurationBuilder.authenticatorAuthorizationUrl(): ProviderConfigurationBuilder = this.property()
    .name("authenticatorAuthorizationUrl")
    .label("Authenticator IDP Authorization Url Overwrite")
    .helpText("Authorization endpoint of the central IDP, used in the Authenticator. Will be extracted from the openid-configuration when left empty.")
    .type(ProviderConfigProperty.STRING_TYPE)
    .add()

fun ProviderConfigurationBuilder.timeoutMs(): ProviderConfigurationBuilder = this.property()
    .name("timeoutMs")
    .label("Authenticator Timeout (ms)")
    .helpText("Timeout in milliseconds until the process of establishing a connection to the Authenticator is aborted (default 20000).")
    .type(ProviderConfigProperty.STRING_TYPE)
    .add()

fun ProviderConfigurationBuilder.openidConfigUrl(): ProviderConfigurationBuilder = this.property()
    .name("openidConfigUrl")
    .label("Gematik IDP openid configuration url")
    .helpText("Url to the Gematik IDP discovery document, which is fetched for authorization and token url.")
    .type(ProviderConfigProperty.STRING_TYPE)
    .add()

fun ProviderConfigurationBuilder.idpTimeoutMs(): ProviderConfigurationBuilder = this.property()
    .name("idpTimeoutMs")
    .label("Gematik IDP timeout (ms)")
    .helpText("Timeout in milliseconds until the process of establishing a connection to the Gematik IDP is aborted (default 10000).")
    .type(ProviderConfigProperty.STRING_TYPE)
    .add()

fun ProviderConfigurationBuilder.idpUserAgent(): ProviderConfigurationBuilder = this.property()
    .name("idpUserAgent")
    .label("Gematik IDP User-Agent")
    .helpText("User-Agent Header as specified in \"gemILF_PS_eRp - A_20015-01\": <Produktname>/<Produktversion> <Herstellername>/<client_id>")
    .type(ProviderConfigProperty.STRING_TYPE)
    .add()

fun ProviderConfigurationBuilder.multipleIdentityMode(): ProviderConfigurationBuilder = this.property()
    .name("multipleIdentityMode")
    .label("Multiple Identities Mode")
    .helpText("If this option is switched on, the current timestamp is appended to the Gematik-IDP-ID, which means that an eHBA can be linked to several users at the same time.")
    .type(ProviderConfigProperty.BOOLEAN_TYPE)
    .add()
