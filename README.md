WS Proxy
========

Skaper en forbindelse mellom GCP og SOAP-tjenester i FSS.

## Hvordan

Alle requests må ha JWT token som Bearer authentication for at ws-proxy skal slippe de gjennom.
Dette må sendes som `X-Proxy-Authorization`-header.

Derfor må alle konsumenter være i accessPolicy-listen til ws-proxy.

Hvorfor `X-Proxy-Authorization`? Jo det har seg slik at Java sin `HttpClient` _fjerner_  `Proxy-Authorization` på alle HTTPS-tilkoblinger automatisk.


### Gandalf

Klienter oppfordres til å bruke Gandalf for å få SAML-assertion fremfor den klassiske STS-en.
Fordi Gandalf også krever autentisering så må dette legges i `Authorization`-headeren.

```
curl \
  -H "Authorization: Basic <basic..>" \
  -H "X-Proxy-Authorization: Bearer <jwt>" \
  https://ws-proxy...fss-pub.nais.io/gandalf/rest/v1/sts/samltoken
```

```mermaid
sequenceDiagram
    box GCP
        participant spenn-simulering
    end
    box FSS
        participant ws-proxy
        participant Gandalf
        participant CICS
    end
    box transparent azure
        participant Token-endpoint
    end
    
    spenn-simulering->>Token-endpoint: Utveksler client secret med JWT scopet for ws-proxy
    Token-endpoint->>spenn-simulering: JWT
    spenn-simulering->>ws-proxy: Bruker jwt i X-Proxy-Authorization<br />og Basic auth i Authorization,<br />og henter SAML assertion
    ws-proxy->>Gandalf: proxy_pass
    Gandalf->>ws-proxy: saml assertion
    ws-proxy->>spenn-simulering: saml assertion 
    spenn-simulering->>ws-proxy: Bruker jwt i X-Proxy-Authorization<br />og kontakter CICSen
    ws-proxy->>CICS: proxy_pass
    CICS->>ws-proxy: response
    ws-proxy->>spenn-simulering: response
    

```

