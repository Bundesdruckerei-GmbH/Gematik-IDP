# Gematik IDP

[IDP plugin](https://www.keycloak.org/docs/latest/server_development/index.html#identity-brokering-apis) to integrate
the gematik central-IDP with the gematik Authenticator application.
It allows a user to log in with an HBA (Heil-Berufs-Ausweis) card by providing HBA and SMCB (Elektronischer
Praxis-/Institutionsausweis) card information. Additionally, HBA- and SMCB-specific IDP mappers are provided.

Please be aware that this plugin was developed for and tested with Keycloak 24, 25, and 26 Quarkus. Starting with
version 22,
Keycloak moved from JavaX to Jakarta, which is why this plugin is incompatible with other Keycloak versions.

## Compability with Gematik Authenticator versions

| Plugin Version     | Authenticator Version |                                                                                                                                                                                                                                      
|--------------------|-----------------------|
| 3.14.0             | 4.17.1 and earlier    |
| 3.13.0 and earlier | 4.16.1 and earlier    |

## Installation

1. Run `mvn clean install` in this directory.
    - By default, the Kotlin dependency is included in the jar. If you already have the Kotlin dependency in place,
      run `mvn clean install -P=-includeKotlin,excludeKotlin`, which excludes Kotlin from the jar.
2. After completion, install the `gematik-idp` jar from the target folder into your Keycloak instance by copying it into
   your Docker container under `/opt/keycloak/providers/` and rebuilding
   the [Quarkus environment](https://www.keycloak.org/server/containers).
3. Add the new Identity Provider `gematik-idp` following the official
   guide [Integrating identity providers](https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker).
   The specific configuration properties are listed below.
4. Set the login theme in the realm where you added the Identity Provider to gematik-idp for full support of
   all features. You can also add the content from `./themes/gematik-idp` to your custom theme if necessary.
    - By default, the theme-resources are included in the jar. If you have your own theme, you can exclude the
      theme-resources by specifying the maven profile `excludeThemeResources`.

## Local Deployment

⚠️**Disclaimer: The following steps and files are not intended
for [production usage](https://www.keycloak.org/server/configuration-production)! Use them at your own risk!** ⚠️

A `docker-compose.yml` file is provided, which starts a Keycloak and a Postgres container, respectively. It also imports
the fully configured Gematik-IDP realm defined under `sample-realm/GematikIDP-ref-idp.json`. This deployment depends on
a parallel running [ref-idp-server](https://github.com/gematik/ref-idp-server) instance, which is also started by the
docker-compose file.

You will need to manually switch the Admin console theme to `gematik-idp` in the master realm. The new admin console
theme
is currently not supported by this plugin.

## Configuration

If you do not see any of these attributes, please make sure to switch to the old admin console theme. The new theme is
currently not supported by this plugin.

| Name                                                            | Value                                                                                                                                               | Description                                                                                                                                                                                                                                        |
|-----------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Multiple Identity Mode                                          | ON or OFF                                                                                                                                           | If this option is switched on, the current timestamp is appended to the Gematik-IDP-ID, which means that an eHBA can be linked to several users at the same time. You will not be able to login with your registered IDP credentials in this case. |
| Authentication Flow                                             | Either single, HBA, SMCB or multiple request                                                                                                        | Choose your preferred authentication flow. When single, HBA or SMCB is selected, only a single request is made to the Gematik-Authenticator, but this flow requires a minimum Authenticator version.                                               |
| Authenticator Version                                           | default: 4.6.0                                                                                                                                      | Minimum compatible version of the authenticator.                                                                                                                                                                                                   |
| Authenticator Timeout (ms)                                      | default: 20000                                                                                                                                      | Timeout in milliseconds until the process of establishing a connection to the Authenticator is aborted                                                                                                                                             |
| Login Timeout (ms)                                              | default: 600000                                                                                                                                     | Timeout in milliseconds until the login process is aborted                                                                                                                                                                                         |
| Gematik IDP openid configuration url                            | https://idp.app.ti-dienste.de/.well-known/openid-configuration <br/> https://idp.zentral.idp.splitdns.ti-dienste.de/.wellknown/openid-configuration | https://idp.app.ti-dienste.de availble from public internet <br/> https://idp.zentral.idp.splitdns.ti-dienste.de/ only available from TI (Telematik-Infrastruktur)                                                                                 |
| Enable token signer certificate validation                      | ON or OFF (default)                                                                                                                                 | If enabled, the ID-Token signing certificate is validated against the full gematik certificate chain. A caching mechanism is used to avoid redundant validations.                                                                                  |
| Enable openid discovery document signing certificate validation | ON or OFF (default)                                                                                                                                 | If enabled, the signing certificate of the JWS openid discovery document, is validated with the full gematik certificate chain.                                                                                                                    |
| Gematik IDP timeout (ms)                                        | default: 10000                                                                                                                                      | Timeout in milliseconds until the process of establishing a connection to the Gematik IDP is aborted                                                                                                                                               |
| Gematik IDP User-Agent                                          |                                                                                                                                                     | User-Agent Header as specified in "gemILF_PS_eRp - A_20015-01": `<Produktname>/<Produktversion> <Herstellername>/<client_id>`                                                                                                                      |
| Client ID                                                       |                                                                                                                                                     | Client ID to verify your request on C-IDP side. Assigned on registration for the IDP on Gematik side                                                                                                                                               |
| Client Secret                                                   |                                                                                                                                                     | Client Secret to verify your request on C-IDP side. Assigned on registration for the IDP on Gematik side                                                                                                                                           |
| Scopes                                                          | default: openid                                                                                                                                     | Scopes to send on each request.                                                                                                                                                                                                                    |
| Authenticator Auto-Launch                                       | ON or OFF (default)                                                                                                                                 | When **ON**, the login page opens the Gematik Authenticator immediately and skips the confirmation modal. When **OFF** (default), the modal is shown and the user must confirm before the app is launched.                                         |
| Authenticator Port Range Start                                  | 1024 (default)                                                                                                                                      | First port of the free‑port range (default 1024). Must be between 1024 and 65535                                                                                                                                                                   |
| Authenticator Port Range End                                    | 65535 (default)                                                                                                                                     | Last port of the free‑port range (default 65535). Must be >= start and within 1024 and 65535                                                                                                                                                       |
| Authenticator Startup Timeout (local HTTP server timeout)       | 10000 (default)                                                                                                                                     | Timeout in milliseconds to establish communication to the authenticator's local HTTP server.                                                                                                                                                       |

Because of limitations in the way Keycloak displays dynamic identity provider settings, it is currently not possible to
define a custom alias or display name for the Gematik-IDP identity provider. This means that only a single Gematik-IDP
identity provider can be configured per realm, since it always gets the alias ``gematik-idp``, and the alias cannot
be shared between identity providers.

If you need to have multiple Gematik-IDP identity providers in your realm or want to define a custom display name,
please consider importing them via a partial realm import. A related discussion took place in the Keycloak project here:

* https://github.com/keycloak/keycloak/pull/24266#issuecomment-1793439822

## TSL certificate validation

On server startup, the gematik TSL XML file is downloaded from the URLs defined in `GEMATIK_IDP_TSL_PRIMARY_URL` or
`GEMATIK_IDP_TSL_SECONDARY_URL` environment variables.
See [gemSpec_TSL](https://gemspec.gematik.de/docs/gemSpec/gemSpec_TSL/gemSpec_TSL_V1.23.0/#A_17680-01) for the available
urls.\
The XML signing certificate is validated against the intermediate certificates from the TSL file **and** the gematik
root certificates from the Keycloak truststore. To add the gematik root certificates to the Keycloak truststore,
configure Keycloak correctly (see
[Keycloak - Configuring trusted certificates](https://www.keycloak.org/server/keycloak-truststore)) and download the
root certificates from:

- PU: https://download.tsl.ti-dienste.de/ECC/ROOT-CA/
- RU: https://download-ref.tsl.ti-dienste.de/ECC/ROOT-CA/

Alternatively, execute the script:

```bash
chmod +x ./gematik-root-certificates/download-certificates.sh &&
./gematik-root-certificates/download-certificates.sh ./gematik-root-certificates
```

All certificates stored in `gematik-root-certificates` are mounted into the Keycloak truststore for local development.

If the signing certificate is valid, the gematik certificate chain is stored and used for future validation of the
openid-configuration JWS's signing certificate.

Additionally, a periodic task is scheduled to update the gematik certificate chain from the TSL XML every 6 hours. The
interval can be overwritten via the environment variable `GEMATIK_IDP_TSL_UPDATE_INTERVAL_MS`.

## ID-Token signer certificate validation

The ID-Token signing certificate can be validated against the intermediate certificates from the TSL file **and** the
gematik
root certificates from the Keycloak truststore. This feature is **disabled by default** and can be enabled via the
`Enable token signer certificate validation` toggle in the admin UI.

A caching mechanism avoids redundant validations: once a certificate is validated, it is cached for 1 hour by default.
The TTL can be overridden via the environment variable `GEMATIK_IDP_CERTIFICATE_VALIDATION_CACHE_TTL_MS`.
The cache is automatically invalidated when the TSL is updated.

## Theme

The template and JavaScript files are supplied as part of the compiled jar and are available under
`/src/main/resources/theme-resources`. To use the scripts, they have to be added to the `theme.properties` file under
scripts:
`scripts=js/gematik-idp.js js/utils/freePortHelper.js`. A sample theme configuration can be found under
`/themes/gematik-idp`. For more information
about extending your own themes, please read
the [Deploying Themes](https://www.keycloak.org/docs/latest/server_development/index.html#deploying-themes) section in
the Keycloak documentation.

### JavaScript cache busting (SERVKO-4490)

Keycloak serves theme resources with a long `Cache-Control` lifetime, so browsers may keep using outdated plugin
JavaScript after a deployment unless the URL changes. The plugin-provided scripts referenced in the sample theme
(`js/gematik-idp.js`, `js/utils/freePortHelper.js`, `js/polling/localHTTPServerPoller.js`) are therefore versioned via a
query parameter:

```properties
scripts=js/gematik-idp.js?v=${env.GEMATIK_IDP_VERSION} js/utils/freePortHelper.js?v=${env.GEMATIK_IDP_VERSION} js/polling/localHTTPServerPoller.js?v=${env.GEMATIK_IDP_VERSION}
```

**Integration contract:**

- Keycloak substitutes `${env.GEMATIK_IDP_VERSION}` with the value of the `GEMATIK_IDP_VERSION` environment variable
  when rendering the login page.
- The variable is **required**: there is no default value. If the variable is missing, Keycloak renders the literal
  `${env.GEMATIK_IDP_VERSION}` placeholder in the script URLs, and cache busting will not work.
- The value must be **immutable** for a given artifact build.

#### Provisioning `GEMATIK_IDP_VERSION`

Depending on your deployment, you must provide this variable to the Keycloak process:

- **Release builds:** Use the Maven version of the `gematik-idp` artifact (e.g., `3.14.0`).
- **SNAPSHOT builds:** Append an immutable build discriminator, such as the CI commit SHA (e.g.,
  `3.47.0-SNAPSHOT-a1b2c3d`).

**Deployment Examples:**

- **Docker Compose:**
  Use a `.env` file or export the variable before running the container:
  ```bash
  export GEMATIK_IDP_VERSION=3.14.0
  docker compose up
  ```
- **Kubernetes:**
  Add the variable to your deployment specification:
  ```yaml
  spec:
    template:
      spec:
        containers:
          - name: keycloak
            env:
              - name: GEMATIK_IDP_VERSION
                value: "3.14.0" # or use valueFrom for ConfigMaps/Secrets
  ```

*Note: Some specialized Keycloak images (e.g., the internal SERVKO image) may derive this value automatically from the
packaged JAR. If you are using a stock Keycloak image, you must provision this variable manually as shown above.*

- **Rolling deployments:** while a rolling deployment has not reached all instances, different instances may serve
  different versions. Browsers that cached the previous version keep using it until its `Cache-Control` lifetime
  expires; this window is inherent to rolling upgrades and cannot be avoided with query-parameter versioning.

When you extend your own theme, add the same `?v=${env.GEMATIK_IDP_VERSION}` parameter to every plugin-provided script
you reference.

### Feature flags

The Gematik IDP plugin provides optional feature flags that can be toggled per realm via realm attributes.

- **Disable4.17LoginFlow**
  *Attribute name*: `Disable4.17LoginFlow`
  When set to `"true"` (case‑insensitive) the plugin disables the new 4.17 authenticator flow. This forces the plugin to
  use the legacy 4.16 flow, which may be required for environments that have not yet upgraded to the 4.17 authenticator
  or where compatibility issues have been observed. The flag is read in
  `GematikIDPResource.generateAuthenticatorFormResponse` and in `GematikIDPUtil.isNewAuthenticatorFlow`. If the flag is
  enabled, the `authenticatorPort` and `handshakeId` query parameters are omitted and the new‑flow specific URLs
  (`authRequestUrl`, `probeAuthenticatorServerUrl`) are not added to the login form.

  To enable the flag for a realm, add the attribute in the Keycloak admin console:

    1. Go to **Realm Settings → Attributes**.
    2. Add a new attribute with **Name** `Disable4.17LoginFlow` and **Value** `true`.
    3. Save the realm.

  Alternatively, set it via the realm JSON import or the Admin REST API:

  ```json
  {
    "attributes": {
      "Disable4.17LoginFlow": "true"
    }
  }
  ```

  The default is **disabled** (the new flow is used).

### Configuring the authentication flow to prevent duplicate IDP Links

If Multiple Identity Mode is set to TRUE, it is possible to create multiple IDP links for one user, but registering the
same IDP for the same user is still not possible and will result in a database error. To prevent this error from
happening, you can extend the appropriate flow that uses Multiple Identity Mode with a conditional branch that
displays a more appropriate error message if a user has already registered an IDP link for your Gematik-IDP, so that
this
illegal state cannot be reached.

1. Go to "Roles > Realm Roles" and create a new role that registered users will be assigned.
2. Go to "Identity Providers > Your Gematik-IDP > Mappers" and create a new mapper of the type "Hardcoded Role" that
   maps to the newly created role
3. Go to "Authentication > Flows" and select your registration authentication flow from the dropdown. Click "Add flow"
   and add a new generic flow
    1. Check the "CONDITIONAL" radio button next to the new entry
    2. Add executions for "Condition - User Role" and "Deny Access" as children of this flow via the "Actions" menu
    3. Check the radio button "REQUIRED" next to both added executions
    4. Configure the "Condition - User Role" execution to check for the newly created role from step 1
    5. Configure the "Deny Access" execution to show the error message. You can localize messages by using a
       message property key here.
4. Move the newly added flow to the top of the list.

Now the OTC Registration flow will check whether the user trying to go through this flow has the newly created role and
will show the "already registered" error page in that case. Otherwise, the flow continues as usual, and the user will be
assigned the newly created role via the hardcoded role mapper on completion of the registration.

## Authentication Flow

Descriptions of the different authentication flows can be found in the following files:

- [Authentication flow for HBA and SMC-B with a single requests to the Gematik-Authenticator](docs/md/multi-auth-flow_up_to_4_16_1.md)
- [Authentication flow for HBA with a single requests to the Gematik-Authenticator](docs/md/hba-auth-flow_up_to_4_16_1.md)
- [Authentication flow for SMC-B with a single requests to the Gematik-Authenticator](docs/md/smcb-auth-flow_up_to_4_16_1.md)

The polling mechanisms diagram for this flow is available here:

- [Authenticator 4.17.0 Polling Mechanisms](docs/md/Authenticator_4_17_PollingMechanisms.md)
