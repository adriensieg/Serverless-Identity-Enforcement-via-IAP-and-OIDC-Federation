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
- All applications are fronted by a Global HTTPS Load Balancer configured with Serverless Network Endpoint Groups (NEGs) pointing to the respective Cloud Run services.
- The domain ailab.com routes via this Load Balancer (e.g., /, /login, /service-desk, etc.).
- A Google-managed SSL certificate and URL map handle HTTPS termination and routing.
- Access and Authentication Requirements
- Applications must be accessible publicly (Internet-facing) but deny direct access to Cloud Run endpoints.
- All requests must pass through the Load Balancer and authentication layer.
- Unauthenticated or unauthorized requests must be blocked without exception.
- Authentication uses OIDC with Azure Entra ID (Microsoft AD-backed IdP).
- The solution must implement SSO with cookie-based sessions and user-based RLS (Row-Level Security) in backend services.
- Backend apps require access to a verified user identity (ID token, email, groups) for access control and personalization.

## Problem Statement
- Cloud Run’s ingress restriction causes 403 errors for IdP callback requests (/auth/login), because the service blocks unauthenticated requests before the OIDC flow completes.
- Current setup cannot complete the OIDC redirect cycle within the app itself — the callback is never seen by the container due to ingress policy.
- You need to maintain both:
    - Public accessibility via Load Balancer, and
    - Strict access control that prevents direct run.app or bypass traffic.

## Proposed Solution

- Enable Identity-Aware Proxy (IAP) on the Load Balancer backend service (the Serverless NEG).
- IAP will:
    - Terminate the OIDC flow with Azure Entra ID directly.
    - Authenticate the user and set the session cookie.
    - Forward only authenticated requests to Cloud Run.
    - Inject signed identity headers (X-Goog-Authenticated-User-Email) and the x-goog-iap-jwt-assertion token.
- Cloud Run will:
    - Trust traffic only from the Load Balancer/IAP (via ingress restriction).
    - Validate IAP’s JWT assertion using Google public keys and the expected audience/issuer.
    - Use the verified identity claims (email, groups) for RLS enforcement.
    - This eliminates the “403-before-OIDC” problem: IAP handles the authentication externally, so Cloud Run only receives authenticated, identity-bearing requests.

## Workforce Identity Federation (WIF) Value

- Since Identity Platform is disallowed, Workforce Identity Federation (WIF) provides a compliant way to integrate Azure Entra ID with GCP for IAM and API-level access, distinct from app authentication.
- Purpose: Allow Azure Entra users to assume GCP IAM roles without creating Google identities.
- Value: Enables federated login from Azure AD to Google Cloud for administrative or programmatic access (e.g., gcloud, APIs).
- Maintains a single corporate IdP (Azure Entra) while enforcing centralized IAM policies in GCP.
- Avoids local Google account management, aligning with enterprise identity governance.
- Note: WIF is for cloud IAM federation, not for front-end application authentication — that function is handled by IAP with OIDC to Azure Entra.

## Flow

```mermaid
sequenceDiagram
    autonumber
    %% Participants
    participant User as User (Browser)
    participant LB as Global HTTPS Load Balancer (Front Door + URL Map + Cert)
    participant IAP as Identity-Aware Proxy (IAP)
    participant IdP as Azure Entra ID (OIDC Provider)
    participant CloudRun as Cloud Run (Serverless NEG backend)
    participant App as App Container (your code)
    participant GCP as Google (IAP JWT public keys / STS)
    rect rgb(240,248,255)
      Note right of LB: LB routes ailab.com traffic → Serverless NEG → Cloud Run\nLB terminates TLS, passes to IAP when IAP enabled on backend
    end

    %% 0. Initial user request (unauthenticated)
    User->>LB: GET https://ailab.com/service-desk
    LB->>IAP: Forward request to IAP (IAP protected backend)
    IAP->>LB: 302 Redirect to IAP auth endpoint (start auth)
    LB->>User: 302 → https://iap.example.com/_/auth?client_id=...&redirect_uri=https://ailab.com/_gcp_gatekeeper
    Note over User,IdP: Browser follows redirect to IAP which proxies OIDC to IdP

    %% 1. IAP initiates OIDC authorization request to Azure Entra
    User->>IAP: Browser GET /_/auth?client_id=... (IAP)
    IAP->>IdP: Authorization Request (OIDC /authorize)\n - response_type=code\n - client_id=IAP-client\n - redirect_uri=IAP callback\n - scope=openid email profile groups
    IdP->>User: 302 -> User login page (if not logged in)
    User->>IdP: User enters credentials / MFA (Azure Entra)
    IdP->>User: POST /authorize -> 302 redirect with ?code=AUTH_CODE to IAP callback URL (LB endpoint)
    User->>LB: Redirect with code to https://ailab.com/_gcp_gatekeeper
    LB->>IAP: Session callback forwarded to IAP

    %% 2. IAP exchanges code for tokens with Azure Entra
    IAP->>IdP: Token Exchange (/token): grant_type=authorization_code, code=AUTH_CODE\n -> returns { id_token (JWT), access_token, refresh_token? }
    IdP-->>IAP: id_token (JWT OIDC), access_token (OAuth2)
    Note right of IAP: IAP validates id_token signature / nonce / exp etc.

    %% 3. IAP establishes user session + sets cookie
    IAP->>User: 302 -> original URL (https://ailab.com/service-desk)\n Set-Cookie: IAP_SID=SESSION; HttpOnly; Secure; SameSite=None
    User->>LB: GET /service-desk (cookie present)
    LB->>IAP: Forward request (cookie included)

    %% 4. IAP creates signed assertion for backend and forwards
    Note right of IAP: On every proxied request IAP either:\n - creates x-goog-iap-jwt-assertion (signed JWT) OR\n - injects convenience headers (X-Goog-Authenticated-User-Email, X-Goog-Authenticated-User-ID)
    IAP->>CloudRun: HTTP/1.1 GET /service-desk\n Headers:\n  - Host: ailab.com\n  - Cookie: IAP_SID=...\n  - X-Goog-Authenticated-User-Email: user@domain.com\n  - X-Goog-Authenticated-User-ID: accounts.google.com:................................\n  - x-goog-iap-jwt-assertion: <IAP_JWT> (signed JWT)
    Note over CloudRun,App: Cloud Run ingress restricted to LB/IAP only\n (Cloud Run configured to deny direct run.app access)

    %% 5. Cloud Run / App validates IAP JWT and extracts identity
    CloudRun->>App: Deliver request to container (same headers)
    App->>GCP: Fetch IAP public keys (cached) and validate x-goog-iap-jwt-assertion\n Validate:\n  - signature using Google's public key\n  - iss == https://cloud.google.com/iap\n  - aud == expected_audience (IAP client id / backend service id)\n  - exp, iat, email presence
    GCP-->>App: public keys (jwks) (or App uses local cache)
    alt JWT valid
      App-->>App: Extract claims: email, sub, name, groups, locale
      App->>App: Map claims to internal identity + apply RLS\n  - Use email / groups / custom claims to filter DB rows
    else invalid
      App->>CloudRun: 401/403 (reject)
    end

    %% 6. Application response (authenticated)
    App->>CloudRun: 200 OK + content
    CloudRun->>LB: Response
    LB->>User: 200 OK (HTML / API response)

    %% 7. IdP callback special-case avoided because IAP handles OIDC
    Note over IdP,App: IdP redirect/callback never needs to reach App. IAP completes the code exchange and only forwards authenticated requests.

    %% ---------------------------
    %% Workforce Identity Federation (WIF) / Admin Programmatic Flow
    %% ---------------------------
    rect rgb(255,248f0)
      Note left of User: Admin wants gcloud / API access using Azure Entra identity\n (no Google account creation)
    end
    participant Admin as Admin (Azure AD User / Service Principal)
    participant STS as Google STS (token exchange)
    participant WIF as Workforce Identity Pool & Provider (GCP)
    participant SA as GCP Service Account (to impersonate)
    participant GCP_API as Google APIs

    %% Admin obtains a SAML/OIDC token from Azure Entra
    Admin->>IdP: Authenticate (Azure AD) -> obtain SAML/OIDC assertion (SAML token or OIDC id_token)
    IdP-->>Admin: SAML/OIDC assertion (signed by Azure)

    %% Admin exchanges assertion for GCP access token using STS & WIF
    Admin->>STS: POST exchangeToken\n - grant_type=urn:ietf:params:oauth:grant-type:token-exchange\n - subject_token_type=urn:ietf:params:oauth:token-type:jwt (or SAML2)\n - subject_token=<Azure_assertion>\n - audience=//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workforcePools/POOL_ID/providers/PROVIDER_ID
    STS->>WIF: Validate provider config (workforcePool + provider mapping)\n (configured to trust Azure Entra tokens)
    STS-->>Admin: short-lived Google access token (oauth2 access_token) scoped to 'iam' to allow impersonation
    Note right of STS: This token is not a long-lived Google account credential

    %% Admin impersonates a Service Account (if configured)
    Admin->>GCP_API: call iamcredentials.generateAccessToken\n - authorization: Bearer <access_token_from_STS>\n - resource: projects/-/serviceAccounts/sa@project.iam.gserviceaccount.com\n - delegates: []\n - scope: https://www.googleapis.com/auth/cloud-platform
    GCP_API-->>Admin: short-lived OAuth2 access token for the SA (iss: https://accounts.google.com)
    Admin->>GCP_API: Use SA token to call GCP APIs (console, gcloud, etc.)
    Note over WIF,SA: Admin actions are auditable in GCP — and no Google accounts were created.

    %% End
    Note over all: Security checks & configuration checklist:\n  - Cloud Run ingress = "internal and load balancer" (blocks run.app)\n  - LB uses Serverless NEG -> Cloud Run (per service)\n  - IAP enabled on LB backend (IAP handles OIDC & cookies)\n  - IAP injects x-goog-iap-jwt-assertion + X-Goog-Authenticated-* headers\n  - App MUST validate the IAP JWT cryptographically (don't trust headers alone)\n  - For admin access, configure Workforce Identity Pools + Provider for Azure Entra\n  - Use STS token exchange + service-account impersonation for short-lived credentials

    %% Footer note
    Note right of App: RLS enforcement:\n  - Extract email / groups from validated IAP JWT\n  - Map to app roles and DB RLS policies\n  - Query DB with principal email claim or use DB row policies per group/role
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




