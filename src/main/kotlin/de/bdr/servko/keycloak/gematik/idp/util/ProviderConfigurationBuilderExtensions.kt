/*
 * Copyright 2026 Bundesdruckerei GmbH
 * For the license, see the accompanying file LICENSE.md
 */

package de.bdr.servko.keycloak.gematik.idp.util

import de.bdr.servko.keycloak.gematik.idp.model.AuthenticationFlowType
import de.bdr.servko.keycloak.gematik.idp.model.GematikIDPConfig
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder


fun ProviderConfigurationBuilder.authenticationFlow(): ProviderConfigurationBuilder = this.property()
    .name(GematikIDPConfig.AUTHENTICATION_FLOW)
    .label("Choose Authentication Flow")
    .helpText("Choose your preferred authentication flow.")
    .defaultValue(AuthenticationFlowType.MULTI.toString())
    .options(
        listOf(
            AuthenticationFlowType.MULTI.toString(),
            AuthenticationFlowType.HBA.toString(),
            AuthenticationFlowType.SMCB.toString()
        )
    )
    .type(ProviderConfigProperty.LIST_TYPE)
    .add()

fun ProviderConfigurationBuilder.authenticatorAuthorizationUrl(): ProviderConfigurationBuilder = this.property()
    .name(GematikIDPConfig.AUTHENTICATOR_AUTHORIZATION_URL)
    .label("Authenticator IDP Authorization Url Overwrite")
    .helpText("Authorization endpoint of the central IDP, used in the Authenticator. Will be extracted from the openid-configuration when left empty.")
    .type(ProviderConfigProperty.STRING_TYPE)
    .add()

fun ProviderConfigurationBuilder.authenticatorVersion(): ProviderConfigurationBuilder = this.property()
    .name(GematikIDPConfig.AUTHENTICATOR_VERSION)
    .label("Authenticator Version")
    .helpText("Minimum compatible version of the authenticator.")
    .type(ProviderConfigProperty.STRING_TYPE)
    .defaultValue(GematikIDPConfig.MINIMUM_AUTHENTICATOR_VERSION.toString())
    .add()

fun ProviderConfigurationBuilder.loginTimeoutMs(): ProviderConfigurationBuilder = this.property()
    .name(GematikIDPConfig.LOGIN_TIMEOUT_MS)
    .label("Login Timeout (ms)")
    .helpText("Timeout in milliseconds until the login process is aborted (default 600000).")
    .type(ProviderConfigProperty.STRING_TYPE)
    .defaultValue(LOGIN_TIMEOUT_MS_VALUE.toString())
    .add()

fun ProviderConfigurationBuilder.timeoutMs(): ProviderConfigurationBuilder = this.property()
    .name(GematikIDPConfig.TIMEOUT_MS)
    .label("Authenticator Timeout (ms)")
    .helpText("Timeout in milliseconds until the process of establishing a connection to the Authenticator is aborted (default 20000).")
    .type(ProviderConfigProperty.STRING_TYPE)
    .defaultValue(AUTHENTICATOR_TIMEOUT_MS_VALUE.toString())
    .add()

fun ProviderConfigurationBuilder.openidConfigUrl(): ProviderConfigurationBuilder = this.property()
    .name(GematikIDPConfig.OPENID_CONFIG_URL)
    .label("Gematik IDP openid configuration url")
    .helpText("Url to the Gematik IDP discovery document, which is fetched for authorization and token url.")
    .type(ProviderConfigProperty.STRING_TYPE)
    .add()

fun ProviderConfigurationBuilder.validateTokenSignerCertificate(): ProviderConfigurationBuilder =
    this.property()
        .name(GematikIDPConfig.VALIDATE_TOKEN_SIGNER_CERTIFICATE)
        .label("Enable token signer cer certificate validation")
        .helpText("Upon activation, the signing certificate is validated against the complete certificate chain of gematik.")
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .add()

fun ProviderConfigurationBuilder.validateOpenIDConfigSigningCertificate(): ProviderConfigurationBuilder =
    this.property()
        .name(GematikIDPConfig.VALIDATE_OPENID_CONFIG_SIGNING_CERTIFICATE)
        .label("Enable openid discovery document signing certificate validation")
        .helpText("If enabled, the signing certificate of the JWS openid discovery document, is validated with the full gematik certificate chain.")
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .add()

fun ProviderConfigurationBuilder.idpTimeoutMs(): ProviderConfigurationBuilder = this.property()
    .name(GematikIDPConfig.IDP_TIMEOUT_MS)
    .label("Gematik IDP timeout (ms)")
    .helpText("Timeout in milliseconds until the process of establishing a connection to the Gematik IDP is aborted (default 10000).")
    .type(ProviderConfigProperty.STRING_TYPE)
    .defaultValue(IDP_TIMEOUT_MS_VALUE.toString())
    .add()

fun ProviderConfigurationBuilder.idpUserAgent(): ProviderConfigurationBuilder = this.property()
    .name(GematikIDPConfig.IDP_USER_AGENT)
    .label("Gematik IDP User-Agent")
    .helpText("User-Agent Header as specified in \"gemILF_PS_eRp - A_20015-01\": <Produktname>/<Produktversion> <Herstellername>/<client_id>")
    .type(ProviderConfigProperty.STRING_TYPE)
    .add()

fun ProviderConfigurationBuilder.multipleIdentityMode(): ProviderConfigurationBuilder = this.property()
    .name(GematikIDPConfig.MULTIPLE_IDENTITY_MODE)
    .label("Multiple Identities Mode")
    .helpText("If this option is switched on, the current timestamp is appended to the Gematik-IDP-ID, which means that an eHBA can be linked to several users at the same time.")
    .type(ProviderConfigProperty.BOOLEAN_TYPE)
    .add()

fun ProviderConfigurationBuilder.authenticatorAutoLaunch(): ProviderConfigurationBuilder = this.property()
    .name(GematikIDPConfig.AUTHENTICATOR_AUTO_LAUNCH)
    .label("Authenticator Auto-Launch")
    .helpText("When enabled, the login page launches the Gematik Authenticator immediately without showing the confirmation modal.")
    .type(ProviderConfigProperty.BOOLEAN_TYPE)
    .add()

fun ProviderConfigurationBuilder.authenticatorPortRangeStart(): ProviderConfigurationBuilder = this.property()
    .name(GematikIDPConfig.AUTHENTICATOR_PORT_RANGE_START)
    .label("Authenticator Port Range Start")
    .helpText(
        "First port of the free‑port range (default " + GematikIDPConfig.AUTHENTICATOR_MIN_PORT + "). Must be between " +
                GematikIDPConfig.AUTHENTICATOR_MIN_PORT + " and " + GematikIDPConfig.AUTHENTICATOR_MAX_PORT + "."
    )
    .type(ProviderConfigProperty.NUMBER_TYPE)
    .defaultValue(GematikIDPConfig.AUTHENTICATOR_MIN_PORT)
    .add()

fun ProviderConfigurationBuilder.authenticatorPortRangeEnd(): ProviderConfigurationBuilder = this.property()
    .name(GematikIDPConfig.AUTHENTICATOR_PORT_RANGE_END)
    .label("Authenticator Port Range End")
    .helpText(
        "Last port of the free‑port range (default " + GematikIDPConfig.AUTHENTICATOR_MAX_PORT + "). Must be >= "
                + GematikIDPConfig().getAuthenticatorPortRangeStart() + " and within " +
                GematikIDPConfig.AUTHENTICATOR_MIN_PORT + "–" + GematikIDPConfig.AUTHENTICATOR_MAX_PORT + "."
    )
    .defaultValue(GematikIDPConfig.AUTHENTICATOR_MAX_PORT)
    .type(ProviderConfigProperty.NUMBER_TYPE)
    .add()

fun ProviderConfigurationBuilder.authenticatorHttpServerTimeoutMs(): ProviderConfigurationBuilder = this.property()
    .name(GematikIDPConfig.AUTHENTICATOR_HTTP_SERVER_TIMEOUT_MS)
    .label("Authenticator Startup Timeout (local HTTP server timeout)")
    .helpText("Timeout in milliseconds to establish communication to the authenticator's local HTTP server. Defaults to 10 seconds.")
    .type(ProviderConfigProperty.NUMBER_TYPE)
    .defaultValue(AUTHENTICATOR_HTTP_SERVER_TIMEOUT_MS_VALUE)
    .add()
