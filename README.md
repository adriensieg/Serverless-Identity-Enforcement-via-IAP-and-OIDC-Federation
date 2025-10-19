# Serverless Identity Enforcement via IAP and OIDC WIF Federation with Azure Entra ID
Zero-Trust OIDC Gateway: Azure Entra ID to Cloud Run via IAP

- [OIDC + IAP Problem Explained](https://github.com/adriensieg/Serverless-Identity-Enforcement-via-IAP-and-OIDC-Federation/blob/master/README.md#oidc--iap-problem-explained)
- [What's Identity Aware Proxy?](https://github.com/adriensieg/Serverless-Identity-Enforcement-via-IAP-and-OIDC-Federation/blob/master/README.md#whats-identity-aware-proxy)
- [Why do I need Workforce Identity Federation?](https://github.com/adriensieg/Serverless-Identity-Enforcement-via-IAP-and-OIDC-Federation/blob/master/README.md#why-do-i-need-workforce-identity-federation)
- [Architecture Overview](https://github.com/adriensieg/Serverless-Identity-Enforcement-via-IAP-and-OIDC-Federation/blob/master/README.md#architecture-overview)
 - [Context and Requirements](https://github.com/adriensieg/Serverless-Identity-Enforcement-via-IAP-and-OIDC-Federation/blob/master/README.md#context-and-requirements)
 - [Network and Access Architecture](https://github.com/adriensieg/Serverless-Identity-Enforcement-via-IAP-and-OIDC-Federation/blob/master/README.md#network-and-access-architecture)
 - [Authentication and Authorization via IAP](https://github.com/adriensieg/Serverless-Identity-Enforcement-via-IAP-and-OIDC-Federation/blob/master/README.md#authentication-and-authorization-via-iap)
 - [Identity Propagation to Cloud Run](https://github.com/adriensieg/Serverless-Identity-Enforcement-via-IAP-and-OIDC-Federation/blob/master/README.md#identity-propagation-to-cloud-run)
 - [Security Enforcement](https://github.com/adriensieg/Serverless-Identity-Enforcement-via-IAP-and-OIDC-Federation/blob/master/README.md#security-enforcement)
 - [Workforce Identity Federation (WIF) Integration](https://github.com/adriensieg/Serverless-Identity-Enforcement-via-IAP-and-OIDC-Federation/blob/master/README.md#workforce-identity-federation-wif-integration)
- [Flow](https://github.com/adriensieg/Serverless-Identity-Enforcement-via-IAP-and-OIDC-Federation/blob/master/README.md#flow)
- [Summary](https://github.com/adriensieg/Serverless-Identity-Enforcement-via-IAP-and-OIDC-Federation/blob/master/README.md#summary)
- [Bibliography](https://github.com/adriensieg/Serverless-Identity-Enforcement-via-IAP-and-OIDC-Federation/blob/master/README.md#bibliography)

## OIDC + IAP Problem Explained
We cannot implement **OIDC authentication** inside **our Cloud Run app** when **IAP is enabled** because of a *chicken-and-egg problem*:
IAP handles authentication **BEFORE** Cloud Run. **IAP intercepts all requests at the Load Balancer**

**The Authentication Deadlock**:
- Our app needs to **handle OIDC callbacks** (from Azure Entra ID) to **authenticate users**
- But Cloud Run **blocks all requests** without **valid IAP authentication**
 - Cloud Run ingress setting: `"internal + load balancer"` = only accepts requests with valid IAP session
 - **Ingress policy** only allows **authenticated traffic**
- The **OIDC callback** can't reach our app because it's **not authenticated yet**
 - **OIDC requirement**: Must receive unauthenticated callbacks to complete authentication
 - **Result**: Our app cannot complete its own authentication flow
- **Result**: `403 error` when Azure tries to redirect back to `/auth/login`
 - The callback never reaches our container

## What's Identity Aware Proxy? 
- Identity-Aware Proxy (IAP) is called **"identity aware"** because it **makes access decisions** based on **who the user is** (**their identity**) rather than just where they're **connecting from** (**like an IP address or network location**).

- **Traditional approach**: A firewall or VPN might say "allow traffic from this IP range" - it's **network-aware** but doesn't really know **who the individual user is**.
- **Identity-Aware approach**: IAP authenticates each user and checks their specific identity (via Google accounts, Cloud Identity, etc.) before granting access to your applications. It asks "Is this specific person authorized?" rather than "Is this request from an authorized network?"

#### How IAP Works (High-Level — Google Cloud Example)
1. **User Request**: A user attempts to access an application URL protected by IAP.
2. **Redirection to Identity Provider**: IAP **intercepts the request** and **redirects the user to our configured identity provider** (~~e.g., Google Sign-In~~) if they don’t have **a valid session**.
3. **Authentication**: The user authenticates with the identity provider.
4. **Token & Identity Assertion**: Upon successful authentication, the identity provider **issues an identity token to IAP**.
5. **Authorization Check**: IAP **verifies the user’s identity** and checks against **IAM policies** to determine **if they are authorized to access the requested resource**. It can also check against **Access Context Manager policies**.
6. **Request Forwarding (with Identity)**: If authorized, IAP **forwards the request to the backend application**. Crucially, IAP adds **signed headers** (e.g., `X-Goog-Authenticated-User-Email`, `X-Goog-Authenticated-User-Id`, `X-Goog-IAP-JWT-Assertion`) containing the **verified user's identity**.
7.	**Application Logic (Optional)**: Your application can (and often should) **use these headers for further fine-grained**, **in-app authorization** or **personalization**.
8.	**Backend Firewall**: Our backend service (e.g., GCE instances, App Engine, GKE) should be **firewalled to only accept traffic from IAP’s known IP ranges** or its specific proxy mechanism.

## Why do I need Workforce Identity Federation? 
[“I don’t want my internal users synced to Google”?](https://medium.com/@oluakin/implementing-external-authentication-using-identity-aware-proxy-iap-quick-tips-093d60c8a9b4)

- **IAP** needs to **understand identities** in **Google Cloud's terms**.
- It needs to **map external identities** to **Google Cloud principals** (like **user accounts** or **service accounts**) so it can make authorization decisions.
  
- *The solution*: Workforce Identity Federation allows us to:
 - **Federate our Azure Entra ID** - Set up a trust relationship between Google Cloud and your Azure tenant
 - **Map external identities** - Configure how Azure Entra ID users/groups map to Google Cloud principals
 - **Authenticate without Cloud Identity** - Users sign in with their Azure credentials, and Google Cloud recognizes them through federation

**IAP handles the OIDC flow for us!** We don't need to implement it in our app.
- **IAP** acts as the **OIDC client**
- When a user hits our app, **IAP intercepts the request**
- IAP redirects them to **authenticate with Azure Entra ID** (via **Workforce Identity Federation**)
- **Azure authenticates the user** and returns **tokens**
- **IAP validates** everything and handles the **token exchange**
- If authorized, IAP forwards the request to our app with **identity headers**
- Our app receives:
 - The **request already authenticated**
 - **Identity information in HTTP headers** (like `X-Goog-IAP-JWT-Assertion`)
 - We can optionally validate the **IAP JWT** if we want extra security, but the heavy lifting is done

**What you configure (not implement)**:
- Set up **Workforce Identity Federation with Azure Entra ID in Google Cloud**
- Configure **IAP to use that federation**
- **Set IAP access policies (who can access what)**

# Architecture Overview
## Context and Requirements
- Multiple **Dockerized applications** are deployed on Google **Cloud Run**.
    - https://ailab.com/ - this is the landing page
    - https://ailab.com/login
    - https://ailab.com/logout
    - https://ailab.com/service-desk
    - https://ailab.com/marketing-immersion 
    - https://ailab.com/asset-scanning
- The platform must be **publicly accessible** (Internet-facing) but **securely authenticated** — **no direct access to Cloud Run’s `run.app` endpoints**.
- Each service has **Ingress restricted** to `“internal + load balancer”` — **direct external access to run.app URLs is denied**.
- **Identity Platform** cannot be used due to corporate policy constraints.
- Authentication and SSO must be handled via **Azure Entra ID (OIDC)** with **cookie-based sessions**.
- **User identity** (email, groups) must be available to backend apps for Row-Level Security (RLS) and personalization.

## Network and Access Architecture
- Each Cloud Run service has **Ingress restricted** to `“Internal + Load Balancer”` — **denies direct Internet access**.
- A **Global HTTPS Load Balancer (GCLB)** fronts all services using **Serverless Network Endpoint Groups (NEGs)**.
- The **domain (ailab.com)** routes through the GCLB using a **Google-managed SSL certificate** and **URL map** for **path-based routing**.
- All traffic flows through this path:
```
User → HTTPS LB (TLS termination) → IAP (auth) → Serverless NEG → Cloud Run → Container.
```

## Authentication and Authorization via IAP
- Identity-Aware Proxy (IAP) is enabled on the backend service (Serverless NEG).
- IAP performs full OIDC Authorization Code Flow with Azure Entra ID — the application does not handle OIDC directly.
- Workforce Identity Federation (WIF) bridges Azure Entra identities with Google Cloud:
- Establishes trust between Azure Entra and Google Cloud.
- Maps Azure users/groups to Google Cloud principals.
- Allows IAP to recognize and authorize users without Cloud Identity accounts.
- IAP sets a secure HttpOnly session cookie (IAP_SID) for SSO.
- Only authenticated and authorized requests are forwarded to Cloud Run.

## Identity Propagation to Cloud Run
- IAP injects **signed identity headers**:
 - `X-Goog-Authenticated-User-Email` – user email (for convenience).
 - `X-Goog-Authenticated-User-ID` – unique user identifier.
 - `x-goog-iap-jwt-assertion` – signed JWT assertion with verified user claims.
   
- Cloud Run services must:
 - Validate the JWT using Google’s public keys (JWKS).
 - Check **issuer**, **audience**, **expiration**, and **email/sub claims**.
 - Use claims for **RLS** and **access control decisions**.

## Security Enforcement
- Cloud Run ingress policy ensures only the Load Balancer/IAP can reach the service.
- Direct access via run.app URLs is completely denied.
- IAP handles authentication externally, preventing **“403-before-OIDC” issues** — apps receive **only validated**, **identity-bearing requests**.
- **Session SSO managed** entirely by IAP; cookies are **secure**, **domain-bound**, and **non-extractable by apps**.

## Workforce Identity Federation (WIF) Integration
- **Azure Entra users** authenticate via **OIDC/SAML**.
- **WIF exchanges** the **Azure assertion** for a **short-lived Google STS token**.
- Optional **Service Account impersonation** can grant scoped access to Google APIs without native Google accounts.
- Enables full **identity continuity** across Azure and Google without duplicating users in Cloud Identity.

# Flow

```mermaid
sequenceDiagram
    participant User as User<br/>(Browser)
    participant LB as Global HTTPS LB<br/>(ailab.com)
    participant IAP as IAP<br/>(Identity-Aware Proxy)
    participant Azure as Azure Entra ID<br/>(IdP)
    participant STS as Google STS<br/>(WIF)
    participant NEG as Serverless NEG<br/>(Router)
    participant CR as Cloud Run Service
    participant JWKS as Google JWKS<br/>(Public Keys)
    participant App as Application<br/>(with RLS)

    %% Initial Request
    User->>+LB: HTTPS Request to ailab.com/service
    Note over LB: TLS Termination<br/>(Google-managed cert)
    LB->>+IAP: Forward request

    %% Check Authentication
    alt No valid IAP_SID cookie
        IAP->>User: Redirect to Azure Entra<br/>(OIDC Auth Code Flow)
        User->>Azure: Authentication request
        Note over Azure: User authenticates<br/>(MFA if required)
        Azure->>User: Auth code + redirect
        User->>IAP: Return with auth code
        
        %% Token Exchange
        IAP->>Azure: Exchange code for token
        Azure->>IAP: ID token + assertions
        
        %% Workforce Identity Federation
        IAP->>+STS: Exchange Azure token<br/>via WIF
        Note over STS: Map Azure identity<br/>to Google principal
        STS-->>-IAP: Google-federated identity
        
        %% Set Session
        IAP->>User: Set IAP_SID cookie
        Note over IAP: Session established
    else Valid IAP_SID cookie exists
        Note over IAP: Validate existing session
    end

    %% Generate IAP JWT
    Note over IAP: Generate signed JWT<br/>with user claims

    %% Forward to Backend
    IAP->>+NEG: Authenticated request<br/>+ Headers:<br/>- x-goog-iap-jwt-assertion<br/>- X-Goog-Authenticated-User-Email<br/>- X-Goog-Authenticated-User-ID
    
    %% Route to Cloud Run
    Note over NEG: Route based on path:<br/>/ → landing<br/>/login → login<br/>/service-desk → service-desk<br/>/marketing-immersion → marketing<br/>/asset-scanning → asset-scan
    
    NEG->>+CR: Forward to appropriate service<br/>(Internal + LB only ingress)
    
    %% JWT Validation
    CR->>+JWKS: Fetch public keys
    JWKS-->>-CR: Return JWKS
    
    Note over CR: Validate JWT:<br/>- Verify signature<br/>- Check issuer (iss)<br/>- Check audience (aud)<br/>- Check expiration (exp)<br/>- Extract claims
    
    alt JWT Valid
        CR->>+App: Forward request with<br/>validated claims
        Note over App: Apply Row-Level Security<br/>using claims:<br/>- email<br/>- groups<br/>- subject (sub)
        App-->>-CR: Process request with RLS
        CR-->>-NEG: Response
        NEG-->>-IAP: Response
        IAP-->>-LB: Response
        LB-->>-User: Response
    else JWT Invalid
        CR-->>NEG: 401 Unauthorized
        NEG-->>IAP: 401 Unauthorized
        IAP-->>LB: 401 Unauthorized
        LB-->>User: 401 Unauthorized
    end

    %% Subsequent Requests
    Note over User,App: Subsequent requests use<br/>IAP_SID cookie for session<br/>(no Azure roundtrip needed)
```

## Summary
- **Complies with policy**: Avoids Identity Platform while achieving federated SSO.
- **Centralized auth**: IAP handles OIDC, token validation, and sessions — apps stay stateless and simple.
- **End-to-end identity assurance**: Every request carries a signed, verifiable identity from Azure Entra ID through Google IAP to Cloud Run.
- **Strong perimeter security**: No public Cloud Run endpoints; all access enforced via HTTPS LB + IAP.
- **Operational simplicity**: No custom auth code, token storage, or redirect handling inside applications.
- **Seamless federation**: WIF maps Azure users directly into Google’s access model for consistent policy enforcement.
- **Scalable and secure**: Fully managed authentication and load balancing for multiple independent microservices.
  
## Bibliography
- https://medium.com/google-cloud/nuts-and-bolts-of-negs-network-endpoint-groups-in-gcp-35b0d06f4691
- https://medium.com/google-cloud/fortifying-your-cloud-zero-trust-with-identity-aware-proxy-iap-ba4a69124e40


