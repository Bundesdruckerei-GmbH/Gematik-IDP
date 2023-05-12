# Gematik IDP

[IDP plugin](https://www.keycloak.org/docs/latest/server_development/index.html#identity-brokering-apis) to integrate
the gematik central-IDP with the gematik Authenticator application.
Allows a user to log in with his HBA (Heil-Berufs-Ausweis) card, supplying HBA and SMCB (Elektronischer
Praxis-/Institutionsausweis) card information. Additionally, HBA- and SMCB-specific IDP mappers are provided.

Please be aware, that this plugin was developed for and tested with Keycloak 20 Quarkus. With Keycloak 20, there were
some changes in some Keycloak classes used by this plugin. If you're running Keycloak 19 or below, please adapt
the ``keycloak.version`` in the POM to 19.0.3 and remove the `null` from the calls to `IdentityBrokerState.decoded`.

With this workaround, it was also confirmed to be working Keycloak 18, while being built for Keycloak 19. It may not
function with other versions.

Keycloak 21 support will be added later, including support for the new admin console theme.

## Installation

1. Run `mvn clean install` in this directory.
2. Run ``npm install`` and ``npm run build:gematik-idp`` in this directory.
3. After completion, install `gematik-idp-1.0.0-SNAPSHOT.jar` into your Keycloak instance by copying it into your Docker
   container under `/opt/keycloak/providers/` and rebuilding
   the [Quarkus environment](https://www.keycloak.org/server/containers).
4. Set the admin theme in your master realm to gematik-idp for the full support of all features.
5. Add the new Identity Provider `gematik-idp` following the official
   guide [Integrating identity providers](https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker)
   . Specific configuration properties are listed below.

## Local Deployment

⚠️**Disclaimer: The following steps and files are not intended
for [production usage](https://www.keycloak.org/server/configuration-production)! Use at your own risk!** ⚠️

A `docker-compose.yml` file is provided, which starts a Keycloak and a Postgres container, respectively. It also imports
the fully configured Gematik-IDP realm defined under `sample-realm/GematikIDP-ref-idp.json`. This deployment depends on
a parallel running [ref-idp-server](https://github.com/gematik/ref-idp-server) instance, which is also started by the
docker-compose file.

You'll need to manually switch the Admin console theme to `gematik-idp` in the master realm. The new admin console theme
is
currently not supported by this plugin.

## Configuration

If you don't see any of these attributes, please make sure to switch to the old admin console theme. We currently don't
support the new theme with this plugin.

| Name                                 | Value                                                                                                                                               | Description                                                                                                                                                                                                                                                                                            |
|--------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Multiple Identity Mode               | ON or OFF                                                                                                                                           | If this option is switched on, the current timestamp is appended to the Gematik-IDP-ID, which means that an eHBA can be linked to several users at the same time. You will not be able to login with your registered IDP credentials in this case.                                                     |
| Authenticator Url                    | http://localhost:8000 <br/> http://localhost:39000 <br/> authenticator://                                                                           | Url to open the Authenticator app <br/> if `authenticator://`, Authenticator app is started, if it has not already been started and response is opened in a new tab <br/> if `http://localhost:8000` or `http://localhost:39000` Authenticator app needs to be running, response is opened in same tab |
| Use new Authentication Flow          | ON or OFF                                                                                                                                           | If this option is switched on, the new Authentication Flow of the Gematik-Authenticator introduced in version 4.0 will be used.                                                                                                                                                                        |
| Authenticator IDP Authorization Url  |                                                                                                                                                     | Authorization endpoint of the central IDP, used in the Authenticator.<br/>Should be extracted from the openid-configuration.                                                                                                                                                                           |
| Authenticator Timeout (ms)           | default: 20000                                                                                                                                      | Timeout in milliseconds until the process of establishing a connection to the Authenticator is aborted                                                                                                                                                                                                 |
| Gematik IDP openid configuration url | https://idp.app.ti-dienste.de/.well-known/openid-configuration <br/> https://idp.zentral.idp.splitdns.ti-dienste.de/.wellknown/openid-configuration | https://idp.app.ti-dienste.de availble from public internet <br/> https://idp.zentral.idp.splitdns.ti-dienste.de/ only available from TI (Telematik-Infrastruktur)                                                                                                                                     |
| Gematik IDP timeout (ms)             | default: 10000                                                                                                                                      | Timeout in milliseconds until the process of establishing a connection to the Gematik IDP is aborted                                                                                                                                                                                                   |
| Gematik IDP User-Agent               |                                                                                                                                                     | User-Agent Header as specified in "gemILF_PS_eRp - A_20015-01": `<Produktname>/<Produktversion> <Herstellername>/<client_id>`                                                                                                                                                                          |
| Client ID                            |                                                                                                                                                     | Client ID to verify your request on C-IDP side. Assigned on registration for the IDP on Gematik side                                                                                                                                                                                                   |
| Default Scopes                       | default: openid                                                                                                                                     | Scopes to send on each request.                                                                                                                                                                                                                                                                        |

## Theme

A base login theme is provided under `/themes` and named `gematik-idp`. This theme contains only the necessary files
for this plugin and can be adapted according to your requirements.

Please make sure to use your standard browser without an incognito window, when using the `authenticator://`
Authenticator Url

If you configured the Authenticator Url `authenticator://` and aren't using the new authentication flow, the Gematik-
Authenticators opens two tabs in your standard browser while authenticating. This is necessary, because the Gematik-cIDP
doesn't support requests for the SMCB and eHBA at the same time and this plugin therefore needs to do two separate calls
to the Gematik-Authenticator. Additionally, the Gematik-Authenticator isn't able to open the response in the same tab,
because of limitations of the `authenticator://` endpoint.

This can cause problems, when you aren't using your standard browser or an incognito window while authenticating. In
this case, the tab opened by the Gematik-Authenticator doesn't know anything about your session, which in turn leeds to
exception in the plugin backend.

### Configuring the authentication flow to prevent duplicate IDP Links

If Multiple Identity Mode is set to TRUE, it is possible to create multiple IDP links for one user, but registering the
same IDP for the same user is still not possible and will result in a database error. To prevent this error from
happening, it is possible to extend the appropriate flow that uses Multiple Identity Mode with a conditional branch that
displays a more appropriate error message if a user has already registered an IDP link for your Gematik-IDP, so this
illegal state cannot be reached.

1. Go to "Roles > Realm Roles" and create a new role that registered users will get assigned
2. Go to "Identity Providers > Your Gematik-IDP > Mappers" and create a new mapper of the type "Hardcoded Role" that
   maps to the newly created role
3. Go to "Authentication > Flows" and select your registration authentication flow from the dropdown. Click "Add flow"
   and add a new generic flow
    1. Check the "CONDITIONAL" radio button next to the new entry
    2. Add executions for "Condition - User Role" and "Deny Access" as children to this flow via the "Actions" menu
    3. Check the radio button "REQUIRED" next to both added executions
    4. Configure the "Condition - User Role" execution to check for the newly create role from step 1
    5. Configure the "Deny Access" execution to show the error message. You're able to localized messages by using a
       message property key here.
4. Move the newly added flow up to the top of the list.

Now the OTC Registration flow will check, if the user that tries to go through this flow has the newly created role and
will show the "already registered" error page in that case. Otherwise, the flow continues as usual and the user will be
assigned the newly created role via the hardcoded role mapper on completion of the registration.

### Prevention of blocked requests to the Gematik-Authenticator

Currently, this plugin makes two requests against the Gematik-Authenticator, as described above: One for the eHBA and on
for the SMCB data.

Some browsers based on Chromium (e.g. Chrome, Edge, etc.) block the second request with an error message when no user
interaction was done between the requests. To prevent this from happening, a modal is shown which the user has to
acknowledge before the Gemaik-Authenticator is opened.

## Old Authentication Flow

A description of the old authentication flow can be found [here](old-auth-flow.md).

## New Authentication Flow

A description of the new authentication flow can be found [here](new-auth-flow.md).
