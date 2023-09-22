# Old Authentication Flow

Supported both by the `authenticator://` (**Gematik Authenticator** version above 3.1) and `https://localhost:39000` (
**Gematik Authenticator** version below 3.1) endpoints configurable via **Authenticator Url's**, while **Use new
Authentication Flow** is set to **OFF** and``Authentication Flow`` set to
``Authentication with a multiple Gematik-Authenticator requests.``.

## Authentication using the `authenticator://` Authenticator Url

**⚠️Please make sure to use your standard browser without an incognito window, when using the `authenticator://`
Authenticator Url with the old authentication flow.⚠️**

If you configured the Authenticator Url `authenticator://` and aren't using the new authentication flow, the Gematik-
Authenticators opens two tabs in your standard browser while authenticating. This is necessary, because the Gematik-cIDP
doesn't support requests for the SMCB and eHBA at the same time and this plugin therefore needs to do two separate calls
to the Gematik-Authenticator. Additionally, the Gematik-Authenticator isn't able to open the response in the same tab,
because of limitations of the `authenticator://` endpoint.

This can cause problems, when you aren't using your standard browser or an incognito window while authenticating. In
this case, the tab opened by the Gematik-Authenticator doesn't know anything about your session, which in turn leeds to
an exception in the plugin backend.

## Flow Diagram

![Flow](/docs/img/flow_old.png)

1. User initiated login
2. User selects the `Login with HBA`, which triggers the gematik-idp
3. First call to Keycloak, initiating the IDP flow
4. Keycloak fetches the openid-configuration from C-IDP: [example configuration](/docs/openid-config.json)
5. C-IDP responds with the openid-configuration as JWS
6. Keycloak verifies the JWS and extracts the following claims:
    - issuer
    - authorization_endpoint
    - token_endpoint
    - jwks_uri
    - uri_puk_idp_enc
    - uri_puk_idp_sig
    - exp (expiration time)
7. After fetching the config, Keycloak redirects the user to /startAuth
8. /startAuth is called from the browser
9. Keycloak generates `code_verifier` and store it in the session of the user
10. Generate the deeplink to the authenticator, passing among other things
    1. challenge_path: url to the C-IDP
    2. redirect_url: url to Keycloak
    3. code_challenge: generated `code_verifier`
    4. scope: Person_ID for HBA, Institutions_ID for SMCB
11. User opens Authenticator app
12. Authenticator app and C-IDP communicate, exchanging certificates and HBA/SMCB data
13. Authenticator calls `redirect_url` **subject to change**
14. Keycloak responds with 302, because Keycloak needs the browser to make the call, to retrieve the user session
15. Authenticator redirects on 302 to the browser / open a new tab
16. User browser calls `redirect_url`
17. Keycloak fetches certificate from C-IDP
18. C-IDP returns certificate
19. Keycloak generates `key_verifier` with the certificate and `code_verifier` from user session
20. Call to C-IDP to retrieve ID-token
21. Responds with json, which contains id_token and access_token as JWE
22. Keycloak decrypts id_token, verifies it and stores [HBA data](/docs/hba-id-token.json) in the session
23. Second deeplink to fetch [SMCB data](/docs/smcb-id-token.json), scope changed to Institutions_ID
    - same flow as 11 - 22 is executed
24. Keycloak updates the user, based on IDP-mapper with the stored HBA/SMCB data
25. Keycloak calls initial redirect_url
26. Return the user to the initial application
