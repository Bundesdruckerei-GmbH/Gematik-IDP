# New Authentication Flow

Supported only in Gematik Authenticator version above 4.6.0 via the `authenticator://` Authenticator Url's with 
``Authentication Flow`` set to ``Authentication with a single Gematik-Authenticator request.``

## Flow Diagram

![Flow](/docs/img/flow_multi.png)

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
9. Keycloak generates `code_verifier` and stores it in the session of the user
10. Generate the deeplink to the Authenticator, passing among other things
    1. challenge_path: url to the C-IDP
       1. Containing a field name ``cardType`` set to multi
    2. redirect_url: url to Keycloak
    3. code_challenge: generated `code_verifier`
11. User opens Authenticator app
12. Authenticator app automatically starts HBA flow with the IDP
13. Browser pulls the authentication status repeatedly, while waiting for the exchange between Gematik-Authenticator and Keycloak to complete
14. Authenticator app and C-IDP communicate, exchanging certificates and HBA/SMCB data
15. Authenticator calls `redirect_url`
16. Keycloak responds with 200 and saves the HBA/SMCB data
17. Keycloak fetches certificate from C-IDP
18. C-IDP returns certificate
19. Keycloak generates `key_verifier` with the certificate and `code_verifier` from user session
20. Call to C-IDP to retrieve ID-token
21. Responds with json, which contains id_token and access_token as JWE
22. Keycloak decrypts id_token, verifies it and stores [HBA data](./docs/hba-id-token.json)/[SMCB data](./docs/smcb-id-token.json) in the session
23. Authenticator app automatically starts HBA flow with the IDP
    - same flow as 14 - 21 is executed
24. Keycloak responses status call from step 12 with 200 and provides the URL to the next step.
25. User browser calls `nextStepUrl` from the status response
26. Keycloak updates the user, based on IDP-mapper with the stored HBA/SMCB data
27. Keycloak calls initial redirect_url
28. Return the user to the initial application
