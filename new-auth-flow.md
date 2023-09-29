# New Authentication Flow

Supported only in Gematik Authenticator version above 4.0 via the `authenticator://` Authenticator Url's, while 
**Use new Authentication Flow** is set to **ON** and``Authentication Flow`` set to 
``Authentication with a multiple Gematik-Authenticator requests.``

## Flow Diagram

![Flow](/docs/img/flow_new.png)

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
10. Generate the deeplink to the Authenticator, passing among other things
    1. challenge_path: url to the C-IDP
    2. redirect_url: url to Keycloak
    3. code_challenge: generated `code_verifier`
    4. scope: Person_ID for HBA, Institutions_ID for SMCB
11. User opens Authenticator app
12. Browser pulls the authentication status repeatedly, while waiting for the exchange between Gematik-Authenticator and Keycloak to complete
13. Authenticator app and C-IDP communicate, exchanging certificates and HBA/SMCB data
14. Authenticator calls `redirect_url`
15. Keycloak responds with 200 and saves the HBA/SMCB data
16. Keycloak fetches certificate from C-IDP
17. C-IDP returns certificate
18. Keycloak generates `key_verifier` with the certificate and `code_verifier` from user session
19. Call to C-IDP to retrieve ID-token
20. Responds with json, which contains id_token and access_token as JWE
21. Keycloak decrypts id_token, verifies it and stores [HBA data](/docs/hba-id-token.json) in the session
22. Keycloak responses status call from step 12 with 200 and provides the URL to the next step.
23. User browser calls `nextStepUrl` from the status response
24. Second deeplink to fetch [SMCB data](/docs/smcb-id-token.json), scope changed to Institutions_ID
    - same flow as 11 - 22 is executed
25. Keycloak updates the user, based on IDP-mapper with the stored HBA/SMCB data
26. Keycloak calls initial redirect_url
27. Return the user to the initial application
