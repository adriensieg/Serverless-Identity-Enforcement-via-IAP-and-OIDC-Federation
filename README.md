# Serverless Identity Enforcement via IAP and OIDC Federation
Zero-Trust OIDC Gateway: Azure Entra ID to Cloud Run via IAP

## Architecture Overview

- Multiple **Dockerized applications** are deployed on Google **Cloud Run**.
    - https://ailab.com/ - this is the landing page
    - https://ailab.com/login
    - https://ailab.com/logout
    - https://ailab.com/service-desk
    - https://ailab.com/marketing-immersion
    - https://ailab.com/asset-scanning 
- Each service has **Ingress restricted** to “internal + load balancer” — **direct external access to run.app URLs is denied**.
- All applications are fronted by a **Global HTTPS Load Balancer** configured with **Serverless Network Endpoint Groups** (**NEGs**) pointing to the respective **Cloud Run services**.
- The domain `ailab.com` routes via this **Load Balancer** (e.g., `/`, `/login`, `/service-desk`, etc.).
- A **Google-managed SSL certificate** and **URL map** handle **HTTPS termination** and **routing**.

## Access and Authentication Requirements
- Applications must be accessible **publicly** (Internet-facing) but **deny direct access to Cloud Run endpoints**.
- All requests must pass through the **Load Balancer** and **authentication layer**.
- **Unauthenticated** or **unauthorized requests** must be **blocked** without exception.
- Authentication uses **OIDC** with **Azure Entra ID** (Microsoft AD-backed IdP).
- The solution must implement **SSO with cookie-based sessions** and **user-based RLS** (Row-Level Security) in backend services.
- Backend apps require access to a **verified user identity** (`ID token`, `email`, `groups`) for **access control** and **personalization**.

## Problem Statement
- Cloud Run’s **ingress restriction** causes **403 errors** for **IdP callback requests** (`/auth/login`), because the service blocks **unauthenticated requests before the OIDC flow completes**.
- Current setup **cannot complete the OIDC redirect cycle within the app itself** — **the callback is never seen by the container due to ingress policy**.
- You need to maintain both:
    - **Public accessibility via Load Balancer**, and
    - **Strict access control** that prevents direct `run.app` or bypass traffic.

## Proposed Solution
- Enable **Identity-Aware Proxy (IAP)** on the **Load Balancer backend service** (the Serverless NEG).
  
- IAP will:
    - **Terminate the OIDC flow** with Azure Entra ID directly.
    - **Authenticate** the user and **set the session cookie**.
    - **Forward** only **authenticated requests** to Cloud Run.
    - **Inject signed identity headers** (`X-Goog-Authenticated-User-Email`) and the `x-goog-iap-jwt-assertion` token.
      
- **Cloud Run** will:
    - **Trust** traffic only from the Load Balancer/IAP (via ingress restriction).
    - **Validate IAP’s JWT assertion** using Google public keys and the expected audience/issuer.
    - Use the **verified identity claims** (`email`, `groups`) for **RLS enforcement**.
    - This eliminates the “403-before-OIDC” problem: **IAP handles the authentication externally**, so **Cloud Run only receives authenticated**, **identity-bearing requests**.

## Workforce Identity Federation (WIF)
- **Value**: Since Identity Platform is disallowed, Workforce Identity Federation (WIF) provides a compliant way to integrate Azure Entra ID with GCP for IAM and API-level access, distinct from app authentication.
- **Purpose**: Allow Azure Entra users to assume GCP IAM roles without creating Google identities.
- **Value**:
    - Enables **federated login** from Azure AD to Google Cloud for administrative or programmatic access (e.g., gcloud, APIs).
    - **Maintains a single corporate IdP** (Azure Entra) while enforcing centralized IAM policies in GCP.
    - **Avoids local Google account management**, aligning with **enterprise identity governance**.
- **Note**: WIF is for cloud IAM federation, not for front-end application authentication — that function is handled by IAP with OIDC to Azure Entra.

## Flow

```mermaid
sequenceDiagram
    autonumber
    participant User as User (Browser)
    participant LB as HTTPS Load Balancer
    participant IAP as Identity-Aware Proxy
    participant IdP as Azure Entra ID (OIDC)
    participant CloudRun as Cloud Run (Serverless NEG)
    participant App as App Container
    participant GCP as Google IAP Keys / STS
    participant Admin as Admin (Azure AD user)
    participant STS as Google STS
    participant WIF as Workforce Identity Federation
    participant SA as GCP Service Account
    participant API as GCP API

    Note right of LB: ailab.com to LB (URL Map, Cert) to IAP to Cloud Run

    User->>LB: GET https://ailab.com/service-desk
    LB->>IAP: Forward to IAP-protected backend
    IAP-->>LB: 302 redirect to IAP auth endpoint
    LB-->>User: 302 to https://iap.googleusercontent.com/_/auth?client_id=...

    User->>IAP: GET /_/auth?client_id=...
    IAP->>IdP: OIDC /authorize (scope=openid email profile)
    IdP-->>User: 302 login page (if not logged in)
    User->>IdP: Enter credentials / MFA
    IdP-->>User: 302 redirect with ?code=AUTH_CODE
    User->>LB: GET /_gcp_gatekeeper?code=AUTH_CODE
    LB->>IAP: Forward to IAP callback

    IAP->>IdP: POST /token (grant_type=authorization_code)
    IdP-->>IAP: id_token (JWT) + access_token
    IAP-->>User: 302 redirect to original URL + Set-Cookie: IAP_SID=SESSION

    User->>LB: GET /service-desk (with IAP_SID cookie)
    LB->>IAP: Forward request (includes cookie)
    IAP->>CloudRun: Forward with IAP headers
    Note over IAP,CloudRun: Headers: X-Goog-Authenticated-User-Email<br/>X-Goog-Authenticated-User-ID<br/>x-goog-iap-jwt-assertion
    Note over CloudRun,App: Cloud Run ingress = internal + LB only

    CloudRun->>App: Deliver request with headers
    App->>GCP: Fetch IAP public keys (JWKS) if needed
    GCP-->>App: Return JWKS
    App->>App: Validate JWT assertion
    Note over App: Check: signature, issuer, audience, expiry
    alt Valid JWT
        App->>App: Extract claims and apply RLS
        App->>CloudRun: 200 OK (authorized)
    else Invalid JWT
        App->>CloudRun: 401/403 Unauthorized
    end
    CloudRun->>LB: Response
    LB->>User: Response (HTML/JSON)
    Note over IdP,App: IdP callback never reaches App - IAP completes OIDC exchange
    Note over Admin,API: WORKFORCE IDENTITY FEDERATION
    Admin->>IdP: Authenticate via Azure Entra
    IdP-->>Admin: Return signed assertion
    Admin->>STS: exchangeToken with Azure assertion
    Note over Admin,STS: grant_type=token-exchange<br/>subject_token=Azure_assertion<br/>audience=workforcePool/provider
    STS->>WIF: Validate provider config (trust Azure Entra)
    STS-->>Admin: short-lived Google access_token
    Admin->>API: iamcredentials.generateAccessToken
    Note over Admin,API: Using access_token to impersonate SA
    API-->>Admin: Short-lived SA OAuth2 token
    Admin->>API: Use SA token for gcloud / API
    Note right of WIF: No Google accounts created<br/>Azure Entra identity federates into GCP IAM
    Note over User,API: Security Checklist:<br/>Cloud Run ingress = LB only<br/>LB uses Serverless NEG<br/>IAP handles OIDC + session cookies<br/>App validates IAP JWT<br/>WIF for IAM federation (no Identity Platform)
```

## Summary

| Concern                                | Resolution                                           |
| -------------------------------------- | ---------------------------------------------------- |
| Direct `run.app` access                | Restrict Cloud Run ingress to LB + IAP               |
| OIDC callback 403                      | Offload OIDC to IAP                                  |
| Authenticated user identity to backend | Validate `x-goog-iap-jwt-assertion`                  |
| Central IdP (Azure Entra)              | Use as OIDC provider for IAP                         |
| No Identity Platform allowed           | Use Workforce Identity Federation for GCP IAM access |

## Key elements

- **Traffic path**: User → LB (TLS termination) → IAP (auth) → Serverless NEG → Cloud Run → Container.
- **Cookies**: IAP sets a secure HttpOnly cookie (IAP_SID) for session SSO; cookie is bound to IAP session.
- **OIDC handling**: IAP performs full OIDC Authorization Code flow with Azure Entra (code → token exchange). App does not handle the IdP callback.
- **Identity headers & assertion**:
    - `x-goog-iap-jwt-assertion` — signed JWT created by IAP. Validate signature, iss, aud, exp.
    - `X-Goog-Authenticated-User-Email` — convenience header (do not trust alone).
    - `X-Goog-Authenticated-User-ID` — subject identifier.
- **Validation**: App must fetch/ cache Google's IAP public keys (JWKS), verify signature, issuer https://cloud.google.com/iap, expected audience (IAP client/back-end ID), expiration, and required claims (email, sub). Only then use claims for RLS.
- **Ingress restriction**: Cloud Run ingress must be set to only allow traffic from Load Balancer (IAP) / internal — prevents direct run.app bypass.
- **Workforce Identity Federation**:
    - Azure Entra users obtain SAML/OIDC assertion
    - Exchange assertion at Google STS/WIF to receive a short-lived Google access token.
    - Optionally impersonate a Service Account (iamcredentials.generateAccessToken) to get SA-scoped short-lived credentials.
    - Use these for gcloud, API, or admin actions — avoids creating Google-managed accounts and abides by your no-Identity-Platform constraint.

## Bibliography
- https://medium.com/google-cloud/nuts-and-bolts-of-negs-network-endpoint-groups-in-gcp-35b0d06f4691
- https://medium.com/google-cloud/fortifying-your-cloud-zero-trust-with-identity-aware-proxy-iap-ba4a69124e40

<img width="468" height="53" alt="image" src="https://github.com/user-attachments/assets/5eaa9a9e-11b3-49dd-a7ed-efc904bc21e0" />




