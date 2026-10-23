# CertiGuard — X.509 Digital Certificate Validation & Expiry Detection Simulator

> **"Verify. Validate. Trust."**  
> An educational, client-side browser simulator for exploring Public Key Infrastructure (PKI), X.509 path validation, and certificate lifecycle expiration rules modelled on **RFC 5280** and **RFC 6125**.

---

## 1. Project Overview & Objectives

**CertiGuard** is a responsive, client-side web application designed to demonstrate the internal mechanics of digital certificate verification used in TLS/HTTPS. Engineered for academic curricula—specifically a third-year B.Tech Information Technology micro-project in Network Security / Applied Cryptography—CertiGuard demystifies how browsers evaluate digital trust.

### Primary Objectives:
- **Demystify PKI Trust**: Visualize how certificates connect through intermediate Certificate Authorities (CAs) to recognized trust anchors.
- **Implement RFC 5280 Path Rules**: Simulate key verification checks including validity windows, basic constraints, key usages, and revocation.
- **Expiry Risk Awareness**: Demonstrate proactive detection of certificate expiration windows with configurable warning thresholds.
- **Practical Understanding of RFC 6125**: Showcase exact and single-label wildcard DNS hostname matching rules.
- **Authentic Certificate Library**: Inspect real, genuine X.509 Root CA certificates from authoritative Certificate Authority repositories.

---

## 2. Core Features

- **Demo Certificate Library**:
  - Direct selection of genuine, verified X.509 certificates from official Certificate Authorities.
  - Entries are identified by their official name and certificate type, avoiding any verdict-revealing labels.
  - Live PEM fetch and raw PEM viewer with quick clipboard copying.
- **8-Point RFC 5280 Verification Engine**:
  1. **Validity Period & Expiry Detection** (`notBefore` & `notAfter` vs evaluation date).
  2. **Issuer-Chain Integrity** (Leaf → Intermediate CA → Root CA path linkage; Root CA self-issuance).
  3. **CA Constraints (Basic Constraints)** (`isCA` flag verification and signing rights per role).
  4. **Trusted Root Anchor** (Evaluation against an embedded simulated trust store).
  5. **RFC 6125 Hostname Matching** (Case-insensitive, trailing dot removal, single-label wildcard handling).
  6. **Key Usage Extensions** (`digitalSignature`, `keyEncipherment`, `certSigning`).
  7. **Cryptographic Signature Verification** (Simulated mathematical digest check).
  8. **Revocation Status** (Simulated CRL / OCSP repository status).
- **Session Analytics & Dynamic Metrics**:
  - Live counters for Total Checked, Valid, Expiring Soon, and Invalid/Expired certificates evaluated during the current browser session.
- **Interactive Workbench**:
  - Test custom inputs or load genuine certificates from the library with a single click.
  - Simulated evaluation date picker to test past, current, and future scenarios without altering the host operating system clock.
  - Visual chain of trust path inspector.
- **Actionable Diagnostic Reporting**:
  - Overall status classification: **TRUSTED** (Green), **WARNING** (Amber), or **REJECTED** (Red).
  - Validation score percentage calculated from passed checks.
  - Primary rejection / warning callout box.
  - Contextual next steps and security recommendations.
  - Local JSON report export (Blob download, zero external dependencies).
  - One-click formatted summary copy to clipboard with fallback.
- **Educational Guide & PKI Architecture**:
  - Visual 3-tier certificate chain diagram.
  - 8 core conceptual cards covering PKI, TLS, and crypto foundations.
  - Direct reference link to RFC 5280.
- **Cybersecurity Operations UI/UX**:
  - Modern dark-mode aesthetic (Deep navy, charcoal, electric cyan, emerald, amber, crimson).
  - Fully responsive across desktop, tablet, and mobile viewport widths.
  - Accessible forms, high contrast, and `prefers-reduced-motion` compliance.

---

## 3. Demo Certificate Library & Certificate Provenance

CertiGuard bundles six certificates in `certificates/`. To maintain educational integrity, the application clearly distinguishes between **authoritative, publicly trusted Root CAs** and **locally generated synthetic test fixtures**:

| Display Name | Filename | Certificate Type | Authority / Issuing Organization | Classification | Primary Educational Scenario |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DigiCert Global Root G2** | `DigiCertGlobalRootG2.pem` | Root CA Certificate | DigiCert, Inc.<br>[cacerts.digicert.com](https://cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem) | Official Root CA | Publicly trusted anchor, valid through 2038 |
| **ISRG Root X1** | `isrgrootx1.pem` | Root CA Certificate | Internet Security Research Group (Let's Encrypt)<br>[letsencrypt.org/certs](https://letsencrypt.org/certs/isrgrootx1.pem) | Official Root CA | Publicly trusted anchor, valid through 2035 |
| **Amazon Root CA 1** | `AmazonRootCA1.pem` | Root CA Certificate | Amazon Trust Services<br>[amazontrust.com/repository](https://www.amazontrust.com/repository/AmazonRootCA1.pem) | Official Root CA | Publicly trusted anchor, valid through 2038 |
| **GTS Root R1** | `gtsr1.pem` | Root CA Certificate | Google Trust Services LLC<br>[pki.goog/repo/certs](https://pki.goog/repo/certs/gtsr1.pem) | Official Root CA | Publicly trusted anchor, valid through 2036 |
| **Northstar Web Services** | `northstar-services.pem` | End-Entity Server Certificate | Northstar Security Services<br>(OpenSSL 3.0 Synthetic Fixture) | Synthetic Test Fixture | Expired validity window (Ended 2024-01-01), matching SAN (`api.northstar-cloud.internal`) |
| **BluePeak Secure Gateway** | `bluepeak-gateway.pem` | End-Entity Server Certificate | BluePeak Technologies<br>(OpenSSL 3.0 Synthetic Fixture) | Synthetic Test Fixture | Hostname mismatch (`cluster-mesh.bluepeak.internal` vs target `gateway.bluepeak.internal`), valid window (2026–2028) |

> [!NOTE]
> **Neutral Naming & Educational Disclosure**: In alignment with realistic PKI operations, certificate entries are assigned realistic organizational names (`Northstar Web Services`, `BluePeak Secure Gateway`) rather than outcome-revealing labels like "Expired Certificate" or "Test Certificate A". These entries are **synthetic laboratory fixtures** generated with OpenSSL for simulation purposes and are **not** real-world organizations or publicly trusted Certificate Authorities.

### Official Root CAs vs. Synthetic Test Fixtures
- **Official Root CA Certificates (1–4)**: Obtained directly from official Certificate Authority repositories. They are genuine, self-signed trust anchors installed in mainstream operating systems and browser trust stores.
- **Synthetic Test Fixtures (5–6)**: Produced locally using OpenSSL 3.0 with standard RSA-2048 keys, real X.509v3 Basic Constraints (`CA:FALSE`), Key Usages (`digitalSignature`, `keyEncipherment`), Extended Key Usage (`serverAuth`), and RFC 5280 Subject Alternative Names. They are issued by synthetic private authorities (`Northstar Internal Issuing CA` and `BluePeak Root Authority`) that are not present in client public trust stores to reflect realistic private PKI behavior.

### Genuine vs. Simulated Engine Mechanics
- **Genuinely Parsed & Verified**:
  - **Validity Arithmetic (RFC 5280 §4.1.2.5)**: Live UTC date comparison between `notBefore`, `notAfter`, and evaluation date, accurately catching expired certificates, not-yet-valid certificates, and inverted date ranges.
  - **Hostname Verification (RFC 6125)**: Case-insensitive SAN parsing, wildcard resolution, and multi-domain evaluation against the target hostname.
  - **Basic Constraints Enforcement (RFC 5280 §4.2.1.9)**: Role verification ensuring end-entity server certificates have `isCA: false` while issuers maintain signing authority.
  - **Key Usage Compliance (RFC 5280 §4.2.1.3)**: Correct validation of TLS server authentication requirements.
  - **Chain Continuity (RFC 5280 §6.1)**: Subject DN to Issuer DN path verification.
- **Simulated / Configured**:
  - **Trust Store Policy (RFC 5280 §6.1.1)**: Checks against the client's configured pre-installed trust store. Unrecognized private authorities are flagged as untrusted root anchors.
  - **Cryptographic Signature Verification**: Simulated digest verification based on key validity state.
  - **Revocation Status (RFC 5280 §5)**: Simulated CRL/OCSP lookup without live network requests.

---

## 4. Technology Stack

- **HTML5**: Semantic document structure, accessible form controls, and inline SVG iconography.
- **CSS3 (Vanilla)**: Custom design system, CSS variables, CSS Grid, Flexbox, glassmorphic card styling, responsive breakpoints, and animations.
- **JavaScript (Vanilla ES6+)**: Client-side state management, RFC-compliant date calculation, wildcard matching algorithms, and JSON export utilities.
- **Zero Dependencies**: No React, Next.js, Node.js backend, Python frameworks, or third-party build tools required.

---

## 5. Multi-Page Architecture & Project Structure

CertiGuard is structured as a modular multi-page web application:

- **Page 1 — Home / Landing Page (`index.html`)**:
  Dedicated overview featuring the cybersecurity hero banner, dual call-to-action buttons (**Start Analysis** and **Demo Analysis**), core capabilities grid, and PKI 3-tier trust chain architecture. Does not contain the certificate library or analysis report below the fold.
- **Page 2 — Demo Certificate Library (`demo.html`)**:
  Dedicated certificate catalog presenting all 6 certificates as visually consistent cards with neutral descriptions, educational test fixture notices, and "View & Analyze" actions.
- **Page 3 — Dedicated Certificate Analysis (`analysis.html?id=<certId>`)**:
  Focused analysis dashboard for the selected certificate. Reads `?id=<certId>` from URL parameters (e.g. `analysis.html?id=digicert-g2`, `analysis.html?id=northstar-services`), displays breadcrumbs, certificate overview grid, 8-point RFC 5280 verification checks, score %, verdict banner, chain inspector, and collapsible raw PEM viewer.
- **Page 4 — Start Analysis Workbench (`start-analysis.html`)**:
  Interactive parameter workbench allowing manual configuration of all X.509 fields, dates, key usages, and root trust anchors, plus a dedicated tab for standard PEM certificate text input.

```text
CertiGuard/
├── certificates/
│   ├── AmazonRootCA1.pem        # Genuine Amazon Root CA 1 certificate (PEM)
│   ├── bluepeak-gateway.pem     # OpenSSL synthetic fixture: Hostname mismatch server certificate
│   ├── DigiCertGlobalRootG2.pem  # Genuine DigiCert Global Root G2 certificate (PEM)
│   ├── gtsr1.pem                 # Genuine Google Trust Services Root R1 certificate (PEM)
│   ├── isrgrootx1.pem            # Genuine ISRG Root X1 (Let's Encrypt) certificate (PEM)
│   ├── northstar-services.pem   # OpenSSL synthetic fixture: Expired server certificate
│   └── manifest.json             # Certificate manifest mapping metadata & sources
├── index.html                    # Page 1: Dedicated landing page
├── demo.html                     # Page 2: Dedicated demo certificate library
├── analysis.html                 # Page 3: Dedicated certificate analysis (?id=<certId>)
├── start-analysis.html           # Page 4: Dedicated custom analysis workbench
├── style.css                     # Cybersecurity theme, typography, layout grids, animations
├── script.js                     # Shared validation logic, router, and export utilities
├── .env                          # Empty environment file
├── .env.example                  # Documentation stating no environment variables are required
├── .gitignore                    # Ignores .env, OS system files, editor configs, and logs
└── README.md                     # Comprehensive project documentation
```

---

## 6. Explanation of Simulated Validation Checks

| Check Name | Specification | Logic & Description |
| :--- | :--- | :--- |
| **1. Validity Period & Expiry** | RFC 5280 §4.1.2.5 | Compares `notBefore` and `notAfter` against the evaluation date in UTC. Rejects if `notAfter < notBefore`, if `evalDate < notBefore` (`NOT YET VALID`), or if `evalDate > notAfter` (`EXPIRED`). Flags `EXPIRING SOON` when remaining days are within the configured threshold. |
| **2. Issuer-Chain Validation** | RFC 5280 §6.1 | Verifies path continuity. For End-Entity certificates, checks that Leaf Issuer matches Intermediate CA Subject, and Intermediate Issuer matches Root CA Subject. For Root CAs, verifies self-issuance (`Issuer == Subject`). |
| **3. CA Constraints** | RFC 5280 §4.2.1.9 | Enforces Basic Constraints. Leaf server certificates must have `isCA: false`. Root and Intermediate CAs must have `isCA: true` and possess Certificate Signing authority. |
| **4. Trusted Root Anchor** | RFC 5280 §6.1.1 | Checks whether the terminating Root CA exists in the simulator's pre-installed trust store (DigiCert G2, ISRG Root X1, Amazon Root CA 1, GTS Root R1). Untrusted roots cause validation failure. |
| **5. Hostname Matching** | RFC 6125 / RFC 5280 §4.2.1.6 | Compares target hostname against Subject Alternative Names (SANs) for TLS server certificates. Enforces single-label wildcard rules (`*.domain.com`). For Root CAs, notes that SAN hostname matching is not applicable. |
| **6. Key Usage Extensions** | RFC 5280 §4.2.1.3 | Validates key purposes. TLS leaf certificates require `Digital Signature` or `Key Encipherment`. CA certificates require `Certificate Signing` (`keyCertSign`) and `CRL Signing`. |
| **7. Signature Verification** | RFC 5280 §4.1.1.3 | Evaluates the simulated mathematical integrity of the cryptographic signature. |
| **8. Revocation Status** | RFC 5280 §5 & RFC 6960 | Checks if the certificate serial number is marked as revoked in simulated CRL / OCSP repository status. |

---

## 7. How to Run & Test Locally

Because CertiGuard utilizes standard asynchronous HTTP requests (`fetch`) to read genuine certificate files from the `certificates/` directory, running through a local web server is recommended.

### Running with Local Python HTTP Server (Recommended)
1. Open a terminal / command prompt in the project directory:
   ```bash
   cd c:\Users\radhi\OneDrive\Desktop\CertiGuard
   ```
2. Start the built-in HTTP server:
   ```bash
   python -m http.server 8000
   ```
3. Open your browser and navigate to:
   ```text
   http://localhost:8000
   ```

### Verification Testing Matrix

| Certificate Entry | Navigation Route | Key Expected Checks | Overall Verdict | Score |
| :--- | :--- | :--- | :--- | :--- |
| **DigiCert Global Root G2** | `analysis.html?id=digicert-g2` | All 8 checks PASS | **TRUSTED** | 100% |
| **ISRG Root X1** | `analysis.html?id=isrg-root-x1` | All 8 checks PASS | **TRUSTED** | 100% |
| **Amazon Root CA 1** | `analysis.html?id=amazon-root-ca-1` | All 8 checks PASS | **TRUSTED** | 100% |
| **GTS Root R1** | `analysis.html?id=gts-root-r1` | All 8 checks PASS | **TRUSTED** | 100% |
| **Northstar Web Services** | `analysis.html?id=northstar-services` | **Check 1 FAILS (EXPIRED)**<br>Check 5 PASSES (`api.northstar-cloud.internal`)<br>Check 4 FAILS (Untrusted Private CA) | **REJECTED** | 75% |
| **BluePeak Secure Gateway** | `analysis.html?id=bluepeak-gateway` | Check 1 PASSES (Valid 2026–2028)<br>**Check 5 FAILS (Hostname mismatch)**<br>Check 4 FAILS (Untrusted Private CA) | **REJECTED** | 75% |

### Multi-Page Navigation Testing Steps
1. **Landing Page (`http://localhost:8000/`)**:
   - Confirm that the hero displays **CertiGuard**, the subtitle, and two prominent CTAs.
   - Confirm that the certificate library and validation report do **not** appear below the fold.
   - Click **Demo Analysis** to open `demo.html`.
2. **Demo Certificate Library (`http://localhost:8000/demo.html`)**:
   - Verify all 6 cards appear with neutral display names.
   - Click **View & Analyze** on **Northstar Web Services**.
3. **Dedicated Analysis Page (`http://localhost:8000/analysis.html?id=northstar-services`)**:
   - Confirm breadcrumb reads: `Home / Demo Certificate Library / Northstar Web Services`.
   - Confirm certificate overview shows `api.northstar-cloud.internal`, valid dates (2023–2024), and synthetic status.
   - Confirm verdict displays **REJECTED** (Check 1 Expired, Check 5 Hostname match).
   - Refresh the browser (`F5` or `Ctrl+R`) and confirm the URL query param preserves the selection.
   - Expand the collapsible **Raw PEM Certificate Payload** and test the **Copy PEM** button.
   - Click **← Back to Demo Library** to return to `demo.html`.
4. **Custom Analysis Workbench (`http://localhost:8000/start-analysis.html`)**:
   - Navigate to **Start Analysis**.
   - Switch between **Parameter Workbench** and **PEM Certificate Input** tabs.
   - Click **Run Certificate Validation** and review the generated 8-point report.

---

## 8. Academic Limitations & Security Disclaimer

- **Educational Simulation**: CertiGuard is designed for academic demonstration and laboratory simulation of RFC 5280 concepts.
- **Parsing Architecture**: The application reads genuine PEM certificate files and utilizes verified X.509 metadata mapped through its manifest. It does not include a full ASN.1 DER parser for arbitrary third-party binary certificates.
- **Simulated Trust & Revocation**: Trust store lookups and revocation checks are executed locally within the client state rather than performing live OCSP network requests or CRL HTTP downloads.
- **Not a Production Validator**: Do not rely on CertiGuard as a substitute for production TLS validation engines (such as OpenSSL, BoringSSL, Go `crypto/x509`, or Java JSSE).

---

## 9. Standards & References

- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280): *Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile*
- [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125): *Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS)*
- [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960): *X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP*
- [CA/Browser Forum Baseline Requirements](https://cabforum.org/baseline-requirements-documents/): *Requirements for the Issuance and Management of Publicly-Trusted Certificates*

---

**CertiGuard** — *Verify. Validate. Trust.*
