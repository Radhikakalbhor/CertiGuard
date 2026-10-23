/**
 * CertiGuard — Comprehensive X.509 Engine Test Suite
 * Validates all 15 mandatory test scenarios from RFC 5280 & RFC 6125 specification.
 */

const fs = require('fs');
const path = require('path');

// Load bundled forge library
const forgeCode = fs.readFileSync(path.join(__dirname, '../lib/forge.min.js'), 'utf8');
const windowObj = {};
const fn = new Function('window', 'exports', 'module', forgeCode);
fn(windowObj, undefined, undefined);
const forge = windowObj.forge;

// Include validation engine logic
function splitPemBundle(pemText) {
  if (!pemText || typeof pemText !== 'string') return [];
  const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const matches = pemText.match(regex);
  return matches ? matches.map(m => m.trim()) : [];
}

function formatHexColons(hexStr) {
  if (!hexStr) return '';
  const clean = hexStr.replace(/[^0-9a-fA-F]/g, '');
  return clean.toUpperCase().match(/.{1,2}/g)?.join(':') || clean.toUpperCase();
}

function toColonHex(bytes) {
  if (!bytes) return '';
  if (typeof bytes === 'string' && /^[0-9a-fA-F]{4,}$/.test(bytes)) {
    return formatHexColons(bytes);
  }
  const hex = typeof bytes === 'string' ? forge.util.bytesToHex(bytes) : bytes;
  return formatHexColons(hex);
}

function formatDn(entity) {
  if (!entity || !entity.attributes) return '';
  return entity.attributes.map(attr => {
    const name = attr.shortName || attr.name || attr.type;
    return `${name} = ${attr.value}`;
  }).join(', ');
}

function getCommonName(entity) {
  if (!entity || !entity.attributes) return '';
  const cn = entity.getField('CN');
  return cn ? cn.value : (entity.attributes[0] ? entity.attributes[0].value : '');
}

function isIpAddress(str) {
  if (!str) return false;
  const s = str.trim();
  const ipv4Regex = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  return ipv4Regex.test(s) || ipv6Regex.test(s);
}

function matchHostnameRfc6125(pattern, host) {
  pattern = (pattern || '').trim().toLowerCase();
  host = (host || '').trim().toLowerCase();

  if (pattern.endsWith('.')) pattern = pattern.slice(0, -1);
  if (host.endsWith('.')) host = host.slice(0, -1);

  if (!pattern || !host) return false;
  if (pattern === host) return true;

  if (pattern.startsWith('*.')) {
    const wildcardDomain = pattern.slice(2);
    if (host === wildcardDomain) return false;

    const expectedSuffix = '.' + wildcardDomain;
    if (host.endsWith(expectedSuffix)) {
      const prefix = host.slice(0, -expectedSuffix.length);
      if (prefix.length > 0 && !prefix.includes('.')) {
        return true;
      }
    }
  }

  return false;
}

function parseX509Certificate(pemText) {
  const pems = splitPemBundle(pemText);
  if (pems.length === 0) {
    throw new Error('No valid PEM certificate found (missing -----BEGIN CERTIFICATE----- markers).');
  }

  const rawCert = forge.pki.certificateFromPem(pems[0]);
  
  let pkAlgo = 'Unknown';
  let keySize = null;
  if (rawCert.publicKey) {
    if (rawCert.publicKey.n) {
      pkAlgo = 'RSA';
      keySize = rawCert.publicKey.n.bitLength();
    } else if (rawCert.publicKey.curve) {
      pkAlgo = 'ECDSA (' + rawCert.publicKey.curve + ')';
    } else {
      pkAlgo = 'Asymmetric Key';
    }
  }

  const sigOid = rawCert.signatureOid;
  const sigAlgoName = forge.pki.oids[sigOid] || sigOid || 'Unknown';

  const bc = rawCert.getExtension('basicConstraints');
  const isCa = bc ? !!bc.cA : false;
  const pathLen = bc && bc.pathLenConstraint !== undefined ? bc.pathLenConstraint : null;

  const ku = rawCert.getExtension('keyUsage');
  const keyUsages = {
    digitalSignature: ku ? !!ku.digitalSignature : false,
    nonRepudiation: ku ? (!!ku.nonRepudiation || !!ku.contentCommitment) : false,
    keyEncipherment: ku ? !!ku.keyEncipherment : false,
    dataEncipherment: ku ? !!ku.dataEncipherment : false,
    keyAgreement: ku ? !!ku.keyAgreement : false,
    keyCertSign: ku ? !!ku.keyCertSign : false,
    cRLSign: ku ? !!ku.cRLSign : false,
    encipherOnly: ku ? !!ku.encipherOnly : false,
    decipherOnly: ku ? !!ku.decipherOnly : false,
    present: !!ku
  };

  const eku = rawCert.getExtension('extKeyUsage');
  const extKeyUsages = {
    serverAuth: eku ? !!eku.serverAuth : false,
    clientAuth: eku ? !!eku.clientAuth : false,
    codeSigning: eku ? !!eku.codeSigning : false,
    emailProtection: eku ? !!eku.emailProtection : false,
    timeStamping: eku ? !!eku.timeStamping : false,
    present: !!eku
  };

  const san = rawCert.getExtension('subjectAltName');
  const sans = {
    dns: [],
    ip: [],
    raw: san && san.altNames ? san.altNames : []
  };
  if (san && san.altNames) {
    san.altNames.forEach(an => {
      if (an.type === 2) sans.dns.push(an.value);
      if (an.type === 7) sans.ip.push(an.ip || an.value);
    });
  }

  const skiExt = rawCert.getExtension('subjectKeyIdentifier');
  const ski = skiExt && skiExt.subjectKeyIdentifier ? toColonHex(skiExt.subjectKeyIdentifier) : null;

  let aki = null;
  const akiExt = rawCert.extensions ? rawCert.extensions.find(e => e.id === '2.5.29.35' || e.name === 'authorityKeyIdentifier') : null;
  if (akiExt && akiExt.value) {
    try {
      const asn1 = forge.asn1.fromDer(akiExt.value);
      if (Array.isArray(asn1.value)) {
        for (const item of asn1.value) {
          if (item.tagClass === 128 && item.type === 0 && item.value) {
            aki = toColonHex(item.value);
            break;
          }
        }
      }
    } catch (err) {}
  }

  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(rawCert)).getBytes();
  const md = forge.md.sha256.create();
  md.update(der);
  const fingerprintSha256 = toColonHex(md.digest().toHex());

  const additionalCerts = [];
  for (let i = 1; i < pems.length; i++) {
    try {
      additionalCerts.push(parseX509Certificate(pems[i]));
    } catch (e) {}
  }

  return {
    rawCert,
    rawPem: pems[0],
    bundlePems: pems,
    additionalCerts,
    subject: formatDn(rawCert.subject),
    subjectCN: getCommonName(rawCert.subject),
    issuer: formatDn(rawCert.issuer),
    issuerCN: getCommonName(rawCert.issuer),
    serialNumber: toColonHex(rawCert.serialNumber),
    notBefore: rawCert.validity.notBefore,
    notAfter: rawCert.validity.notAfter,
    publicKeyAlgorithm: pkAlgo,
    keySize: keySize,
    signatureAlgorithm: sigAlgoName,
    isCa,
    pathLenConstraint: pathLen,
    hasBasicConstraints: !!bc,
    keyUsages,
    extKeyUsages,
    sans,
    ski,
    aki,
    fingerprintSha256
  };
}

function loadTrustedRoots() {
  const rootFiles = [
    { id: 'digicert-g2', name: 'DigiCert Global Root G2', file: 'DigiCertGlobalRootG2.pem' },
    { id: 'isrg-root-x1', name: 'ISRG Root X1', file: 'isrgrootx1.pem' },
    { id: 'amazon-root-ca-1', name: 'Amazon Root CA 1', file: 'AmazonRootCA1.pem' },
    { id: 'gts-root-r1', name: 'GTS Root R1', file: 'gtsr1.pem' }
  ];
  return rootFiles.map(rf => {
    const pem = fs.readFileSync(path.join(__dirname, '../certificates', rf.file), 'utf8');
    return {
      id: rf.id,
      name: rf.name,
      parsed: parseX509Certificate(pem)
    };
  });
}

const trustStore = loadTrustedRoots();

function validateParsedCertificate(certObj, options = {}) {
  const evalDate = options.evaluationDate ? new Date(options.evaluationDate) : new Date();
  const warningDays = parseInt(options.warningThreshold || 30, 10);
  const targetHost = (options.hostnameToVerify || '').trim();
  const candidateChain = options.chainBundle || certObj.additionalCerts || [];

  const checks = [];
  let isRejected = false;
  let isWarning = false;
  let isIndeterminate = false;
  let primaryReason = '';

  const isSelfSigned = (certObj.subject === certObj.issuer) || (certObj.subjectCN && certObj.subjectCN === certObj.issuerCN);
  const isRootCa = certObj.isCa && isSelfSigned;

  // Check 1: Validity Period
  let check1Status = 'PASS';
  let check1Message = '';
  let periodState = 'VALID';
  let daysDiff = 0;

  if (!certObj.notBefore || !certObj.notAfter) {
    check1Status = 'FAIL';
    periodState = 'INVALID_DATES';
    check1Message = 'Validity dates are missing or corrupt in X.509 structure.';
  } else if (certObj.notAfter.getTime() < certObj.notBefore.getTime()) {
    check1Status = 'FAIL';
    periodState = 'INVERTED_DATES';
    check1Message = 'Fatal date range error: notAfter precedes notBefore.';
  } else if (evalDate.getTime() < certObj.notBefore.getTime()) {
    check1Status = 'FAIL';
    periodState = 'NOT_YET_VALID';
    const daysUntil = Math.ceil((certObj.notBefore.getTime() - evalDate.getTime()) / 86400000);
    check1Message = `Certificate is NOT YET VALID. Starts in ${daysUntil} day(s) on ${certObj.notBefore.toISOString().split('T')[0]}.`;
  } else if (evalDate.getTime() > certObj.notAfter.getTime()) {
    check1Status = 'FAIL';
    periodState = 'EXPIRED';
    const daysAgo = Math.floor((evalDate.getTime() - certObj.notAfter.getTime()) / 86400000);
    check1Message = `Certificate is EXPIRED. Exceeded notAfter by ${daysAgo} day(s) (expired on ${certObj.notAfter.toISOString().split('T')[0]}).`;
  } else {
    daysDiff = Math.floor((certObj.notAfter.getTime() - evalDate.getTime()) / 86400000);
    if (daysDiff <= warningDays) {
      check1Status = 'WARN';
      periodState = 'EXPIRING_SOON';
      check1Message = `Certificate is EXPIRING SOON! Only ${daysDiff} day(s) remaining (Threshold: ≤ ${warningDays} days).`;
    } else {
      check1Status = 'PASS';
      periodState = 'VALID';
      check1Message = `Certificate is currently within its validity window. ${daysDiff} day(s) remaining until ${certObj.notAfter.toISOString().split('T')[0]}.`;
    }
  }

  checks.push({
    id: 'validity_period',
    name: 'Check 1: Validity Period & Expiry Detection',
    status: check1Status,
    periodState,
    daysDiff,
    explanation: check1Message
  });
  if (check1Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check1Message; }
  else if (check1Status === 'WARN') { isWarning = true; if (!primaryReason) primaryReason = check1Message; }

  // Candidate Issuer Search
  let candidateIssuer = null;
  if (!isSelfSigned) {
    candidateIssuer = candidateChain.find(c => c.subject === certObj.issuer || (c.subjectCN && c.subjectCN === certObj.issuerCN));
    if (!candidateIssuer) {
      const trustedMatch = trustStore.find(t => t.parsed.subject === certObj.issuer || (t.parsed.subjectCN && t.parsed.subjectCN === certObj.issuerCN));
      if (trustedMatch) candidateIssuer = trustedMatch.parsed;
    }
  }

  // Check 2: Issuer-Chain Validation
  let check2Status = 'PASS';
  let check2Message = '';

  if (isRootCa) {
    try {
      const verified = certObj.rawCert.verify(certObj.rawCert);
      if (verified) {
        check2Status = 'PASS';
        check2Message = `Self-issued Root CA trust anchor: Subject and Issuer match ("${certObj.subjectCN}"), and self-signature verifies mathematically per RFC 5280 §6.1.`;
      } else {
        check2Status = 'FAIL';
        check2Message = 'Self-issued Root CA anchor verification failed: Cryptographic signature mismatch.';
      }
    } catch (err) {
      check2Status = 'FAIL';
      check2Message = `Self-issued Root CA verification failed: ${err.message}`;
    }
  } else if (candidateIssuer) {
    try {
      const verified = candidateIssuer.rawCert.verify(certObj.rawCert);
      if (verified) {
        check2Status = 'PASS';
        check2Message = `Valid chain link: Certificate is cryptographically signed by issuer ("${candidateIssuer.subjectCN || candidateIssuer.subject}").`;
      } else {
        check2Status = 'FAIL';
        check2Message = `Broken chain link: Issuer signature verification failed against candidate issuer ("${candidateIssuer.subjectCN || candidateIssuer.subject}").`;
      }
    } catch (err) {
      check2Status = 'FAIL';
      check2Message = `Chain verification cryptographic error: ${err.message}`;
    }
  } else {
    check2Status = 'INDETERMINATE';
    check2Message = `Chain verification indeterminate: Issuing certificate ("${certObj.issuerCN || certObj.issuer}") is missing from chain bundle and local trust store. Complete path validation cannot be performed without the issuer certificate.`;
  }

  checks.push({
    id: 'issuer_chain',
    name: 'Check 2: Issuer-Chain Validation',
    status: check2Status,
    explanation: check2Message
  });
  if (check2Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check2Message; }
  else if (check2Status === 'INDETERMINATE') { isIndeterminate = true; }

  // Check 3: CA Constraints & Basic Constraints
  let check3Status = 'PASS';
  let check3Message = '';

  if (certObj.isCa) {
    if (certObj.keyUsages.present && !certObj.keyUsages.keyCertSign) {
      check3Status = 'FAIL';
      check3Message = 'Basic Constraints Violation: Certificate asserts CA:TRUE but lacks Certificate Signing (keyCertSign) in Key Usage extension.';
    } else {
      check3Status = 'PASS';
      check3Message = `Valid Basic Constraints: Certificate asserts CA:TRUE${certObj.pathLenConstraint !== null ? ' (pathLen=' + certObj.pathLenConstraint + ')' : ''} with valid signing authority per RFC 5280 §4.2.1.9.`;
    }
  } else {
    if (certObj.keyUsages.keyCertSign) {
      check3Status = 'FAIL';
      check3Message = 'Basic Constraints Violation: Non-CA certificate asserts Certificate Signing authority (keyCertSign), which is strictly reserved for CA certificates.';
    } else {
      check3Status = 'PASS';
      check3Message = 'Valid Basic Constraints: Certificate is correctly designated as end-entity (CA:FALSE / non-CA).';
    }
  }

  checks.push({
    id: 'ca_constraints',
    name: 'Check 3: CA Constraints (Basic Constraints)',
    status: check3Status,
    explanation: check3Message
  });
  if (check3Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check3Message; }

  // Check 4: Trust-Anchor Validation
  let check4Status = 'PASS';
  let check4Message = '';

  if (isRootCa) {
    const trustedMatch = trustStore.find(t => t.parsed.fingerprintSha256 === certObj.fingerprintSha256 || t.parsed.serialNumber === certObj.serialNumber);
    if (trustedMatch) {
      check4Status = 'PASS';
      check4Message = `Root anchor verified: Certificate is installed in the client's trusted root store ("${trustedMatch.name}").`;
    } else {
      check4Status = 'FAIL';
      check4Message = `Untrusted Root: Certificate claims to be a root authority ("${certObj.subjectCN}"), but is NOT present in the client's pre-configured trust store.`;
    }
  } else if (candidateIssuer) {
    const trustedRoot = trustStore.find(t => t.parsed.fingerprintSha256 === candidateIssuer.fingerprintSha256 || t.parsed.subject === candidateIssuer.subject);
    if (trustedRoot) {
      check4Status = 'PASS';
      check4Message = `Chain terminates at verified trusted root anchor: "${trustedRoot.name}".`;
    } else {
      check4Status = 'FAIL';
      check4Message = `Untrusted Root: Certificate chain terminates at an untrusted authority ("${candidateIssuer.subjectCN || candidateIssuer.subject}") not present in client trust store.`;
    }
  } else {
    check4Status = 'INDETERMINATE';
    check4Message = 'Trust anchor evaluation incomplete: Issuing certificate is missing, so termination at a trusted root cannot be established.';
  }

  checks.push({
    id: 'trusted_root',
    name: 'Check 4: Trusted Root Anchor',
    status: check4Status,
    explanation: check4Message
  });
  if (check4Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check4Message; }
  else if (check4Status === 'INDETERMINATE') { isIndeterminate = true; }

  // Check 5: Hostname & SAN Validation
  let check5Status = 'PASS';
  let check5Message = '';

  if (isRootCa) {
    check5Status = 'PASS';
    check5Message = 'Informational: RFC 6125 hostname matching applies to TLS end-entity server certificates. As an authoritative Root CA anchor, SAN verification is not applicable.';
  } else {
    const hostToCheck = targetHost || certObj.subjectCN || '';
    if (!hostToCheck) {
      check5Status = 'FAIL';
      check5Message = 'Hostname verification error: No target hostname or Subject Common Name provided for verification.';
    } else if (certObj.sans.raw.length === 0) {
      check5Status = 'FAIL';
      check5Message = 'Missing Subject Alternative Names: Certificate lacks SAN extension. RFC 6125 prohibits relying on Subject Common Name.';
    } else if (isIpAddress(hostToCheck)) {
      const ipMatch = certObj.sans.ip.find(ip => ip.trim() === hostToCheck);
      if (ipMatch) {
        check5Status = 'PASS';
        check5Message = `IP SAN match confirmed: Target IP "${hostToCheck}" matches IP SAN entry "${ipMatch}".`;
      } else {
        check5Status = 'FAIL';
        check5Message = `IP SAN mismatch: Target IP "${hostToCheck}" does not match certificate IP SANs: [${certObj.sans.ip.join(', ') || 'None'}]. (DNS SAN entries are not valid for IP matching per RFC 6125).`;
      }
    } else {
      let matchedDns = null;
      for (const dnsSan of certObj.sans.dns) {
        if (matchHostnameRfc6125(dnsSan, hostToCheck)) {
          matchedDns = dnsSan;
          break;
        }
      }
      if (matchedDns) {
        check5Status = 'PASS';
        check5Message = `Hostname match confirmed: Requested host "${hostToCheck}" matches DNS SAN entry "${matchedDns}" per RFC 6125.`;
      } else {
        check5Status = 'FAIL';
        check5Message = `Hostname mismatch! Requested host "${hostToCheck}" does not match DNS SAN entries: [${certObj.sans.dns.join(', ')}].`;
      }
    }
  }

  checks.push({
    id: 'hostname_matching',
    name: 'Check 5: Hostname Matching (RFC 6125)',
    status: check5Status,
    explanation: check5Message
  });
  if (check5Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check5Message; }

  // Check 6: Key Usage & EKU
  let check6Status = 'PASS';
  let check6Message = '';

  if (!certObj.keyUsages.present && !certObj.extKeyUsages.present) {
    check6Status = 'NOT CHECKED';
    check6Message = 'Key Usage and Extended Key Usage extensions are absent. Purpose cannot be strictly confirmed against TLS server profile per RFC 5280 §4.2.1.3.';
  } else if (certObj.isCa) {
    if (!certObj.keyUsages.keyCertSign) {
      check6Status = 'FAIL';
      check6Message = 'Incompatible Key Usage: Certificate Authority requires Certificate Signing (keyCertSign).';
    } else {
      check6Status = 'PASS';
      check6Message = 'Key Usage verified: Possesses Certificate Signing (keyCertSign) and CRL Signing per RFC 5280.';
    }
  } else {
    const hasSigOrEnc = certObj.keyUsages.digitalSignature || certObj.keyUsages.keyEncipherment;
    const hasServerAuth = certObj.extKeyUsages.present ? certObj.extKeyUsages.serverAuth : true;

    if (!hasSigOrEnc && certObj.keyUsages.present) {
      check6Status = 'FAIL';
      check6Message = 'Incompatible Key Usage: TLS end-entity server certificates require Digital Signature and/or Key Encipherment.';
    } else if (certObj.keyUsages.keyCertSign) {
      check6Status = 'FAIL';
      check6Message = 'Illegal Key Usage: End-entity certificate asserts Certificate Signing authority (keyCertSign).';
    } else if (certObj.extKeyUsages.present && !hasServerAuth) {
      check6Status = 'FAIL';
      check6Message = 'Incompatible Extended Key Usage: Certificate lacks TLS Web Server Authentication (id-kp-serverAuth).';
    } else {
      check6Status = 'PASS';
      check6Message = 'Key Usage verified: Possesses valid cryptographic key usages (Digital Signature / Key Encipherment) and TLS Server Authentication EKU.';
    }
  }

  checks.push({
    id: 'key_usage',
    name: 'Check 6: Key Usage & Extended Key Usage',
    status: check6Status,
    explanation: check6Message
  });
  if (check6Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check6Message; }

  // Check 7: Cryptographic Signature Integrity
  let check7Status = 'PASS';
  let check7Message = '';

  if (isSelfSigned) {
    try {
      const verified = certObj.rawCert.verify(certObj.rawCert);
      if (verified) {
        check7Status = 'PASS';
        check7Message = `Signature Verified: Self-signed digital signature mathematically verified using certificate's ${certObj.publicKeyAlgorithm} ${certObj.keySize ? certObj.keySize + '-bit' : ''} public key (${certObj.signatureAlgorithm}).`;
      } else {
        check7Status = 'FAIL';
        check7Message = 'Signature Verification Failed: Digital signature does not match public key (corrupt or tampered).';
      }
    } catch (err) {
      check7Status = 'FAIL';
      check7Message = `Signature Verification Failed: ${err.message}`;
    }
  } else if (candidateIssuer) {
    try {
      const verified = candidateIssuer.rawCert.verify(certObj.rawCert);
      if (verified) {
        check7Status = 'PASS';
        check7Message = `Signature Verified: Digital signature cryptographically verified using issuer's public key ("${candidateIssuer.subjectCN || candidateIssuer.subject}").`;
      } else {
        check7Status = 'FAIL';
        check7Message = 'Signature Verification Failed: Digital signature does not match issuer public key.';
      }
    } catch (err) {
      check7Status = 'FAIL';
      check7Message = `Signature verification error: ${err.message}`;
    }
  } else {
    check7Status = 'INDETERMINATE';
    check7Message = `Cryptographic signature check could not be completed because issuer certificate ("${certObj.issuerCN || certObj.issuer}") was not provided. A signature cannot be verified without the issuer's public key.`;
  }

  checks.push({
    id: 'signature_verification',
    name: 'Check 7: Cryptographic Signature Integrity',
    status: check7Status,
    explanation: check7Message
  });
  if (check7Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check7Message; }
  else if (check7Status === 'INDETERMINATE') { isIndeterminate = true; }

  // Check 8: Revocation Status
  const check8Status = 'NOT CHECKED';
  const check8Message = 'UNKNOWN — Revocation status not checked. In this local offline verification environment, live OCSP responder and CRL distribution point network queries are disabled to preserve privacy and offline operation. Certificate is not assumed unrevoked.';

  checks.push({
    id: 'revocation_status',
    name: 'Check 8: Revocation Status (CRL/OCSP)',
    status: check8Status,
    explanation: check8Message
  });

  let overallVerdict = 'TRUSTED';
  if (isRejected) {
    overallVerdict = 'REJECTED';
  } else if (isWarning) {
    overallVerdict = 'WARNING';
  } else if (isIndeterminate) {
    overallVerdict = 'INDETERMINATE';
    primaryReason = 'Chain verification or cryptographic signature check is indeterminate due to missing issuer certificates.';
  }

  const passedCount = checks.filter(c => c.status === 'PASS').length;
  const scorePercent = Math.round((passedCount / checks.length) * 100);

  return {
    verdict: overallVerdict,
    score: scorePercent,
    passedCount,
    totalCount: checks.length,
    primaryReason: primaryReason || 'All verifiable checks passed successfully.',
    checks
  };
}

// ============================================================================
// TEST SUITE EXECUTION (15 Scenarios)
// ============================================================================
console.log('================================================================');
console.log('CertiGuard Automated X.509 Test Suite (15 Test Scenarios)');
console.log('================================================================\n');

const fixtures = JSON.parse(fs.readFileSync(path.join(__dirname, '../scratch/test_fixtures.json'), 'utf8'));

let testsPassed = 0;
let testsFailed = 0;

function assert(condition, testName, detail = '') {
  if (condition) {
    console.log(`[PASS] ${testName}`);
    testsPassed++;
  } else {
    console.error(`[FAIL] ${testName} - Detail: ${detail}`);
    testsFailed++;
  }
}

// Scenario 1: A valid, unexpired certificate
{
  const pem = fs.readFileSync(path.join(__dirname, '../certificates/DigiCertGlobalRootG2.pem'), 'utf8');
  const cert = parseX509Certificate(pem);
  const res = validateParsedCertificate(cert, { evaluationDate: '2026-10-23' });
  assert(res.checks[0].status === 'PASS' && res.checks[0].periodState === 'VALID', 'Scenario 1: Valid unexpired certificate detected as VALID');
}

// Scenario 2: An expired certificate
{
  const pem = fs.readFileSync(path.join(__dirname, '../certificates/northstar-services.pem'), 'utf8');
  const cert = parseX509Certificate(pem);
  const res = validateParsedCertificate(cert, { evaluationDate: '2026-10-23' });
  assert(res.checks[0].status === 'FAIL' && res.checks[0].periodState === 'EXPIRED', 'Scenario 2: Expired certificate detected as EXPIRED');
}

// Scenario 3: A certificate that is not yet valid
{
  const cert = parseX509Certificate(fixtures.futureCertPem);
  const res = validateParsedCertificate(cert, { evaluationDate: '2026-10-23' });
  assert(res.checks[0].status === 'FAIL' && res.checks[0].periodState === 'NOT_YET_VALID', 'Scenario 3: Future certificate detected as NOT_YET_VALID');
}

// Scenario 4: A malformed PEM input
{
  let threw = false;
  try {
    parseX509Certificate('-----BEGIN CERTIFICATE-----\nINVALID_BASE64_CORRUPT_BYTES===\n-----END CERTIFICATE-----');
  } catch (e) {
    threw = true;
  }
  assert(threw, 'Scenario 4: Malformed PEM input raises an explicit parsing error gracefully');
}

// Scenario 5: Certificate with hostname matching its DNS SAN
{
  const cert = parseX509Certificate(fixtures.validCustomCertPem);
  const resExact = validateParsedCertificate(cert, { hostnameToVerify: 'secure-portal.cloudcorp.io' });
  const resWildcard = validateParsedCertificate(cert, { hostnameToVerify: 'api.cloudcorp.io' });
  assert(resExact.checks[4].status === 'PASS' && resWildcard.checks[4].status === 'PASS', 'Scenario 5: Exact DNS and single-label wildcard SAN matching succeed');
}

// Scenario 6: Hostname mismatch
{
  const pem = fs.readFileSync(path.join(__dirname, '../certificates/bluepeak-gateway.pem'), 'utf8');
  const cert = parseX509Certificate(pem);
  const res = validateParsedCertificate(cert, { hostnameToVerify: 'gateway.bluepeak.internal' });
  assert(res.checks[4].status === 'FAIL', 'Scenario 6: Hostname mismatch fails Check 5');
}

// Scenario 7: IP address compared against DNS SAN entries
{
  const cert = parseX509Certificate(fixtures.ipSanCertPem);
  // IP 192.168.1.100 is in IP SAN -> should PASS
  const resIpMatch = validateParsedCertificate(cert, { hostnameToVerify: '192.168.1.100' });
  // IP 10.0.0.1 is NOT in IP SAN -> should FAIL
  const resIpMismatch = validateParsedCertificate(cert, { hostnameToVerify: '10.0.0.1' });
  assert(resIpMatch.checks[4].status === 'PASS' && resIpMismatch.checks[4].status === 'FAIL', 'Scenario 7: IP address matched strictly against IP SANs per RFC 6125');
}

// Scenario 8: Certificate with a missing issuer certificate
{
  const pem = fs.readFileSync(path.join(__dirname, '../certificates/northstar-services.pem'), 'utf8');
  const cert = parseX509Certificate(pem);
  const res = validateParsedCertificate(cert);
  assert(res.checks[1].status === 'INDETERMINATE' && res.checks[6].status === 'INDETERMINATE', 'Scenario 8: Missing issuer marks Check 2 and Check 7 as INDETERMINATE');
}

// Scenario 9: Certificate with an invalid cryptographic signature
{
  const cert = parseX509Certificate(fixtures.tamperedCertPem);
  const caCert = parseX509Certificate(fixtures.untrustedCaPem);
  const res = validateParsedCertificate(cert, { chainBundle: [caCert] });
  assert(res.checks[6].status === 'FAIL', 'Scenario 9: Cryptographically invalid signature detected as FAIL');
}

// Scenario 10: Untrusted root or chain
{
  const cert = parseX509Certificate(fixtures.untrustedCaPem);
  const res = validateParsedCertificate(cert);
  assert(res.checks[3].status === 'FAIL', 'Scenario 10: Self-signed root absent from trust store detected as Untrusted Root Anchor');
}

// Scenario 11: CA certificate with invalid Basic Constraints for its role
{
  const cert = parseX509Certificate(fixtures.invalidBcCaPem);
  const res = validateParsedCertificate(cert);
  assert(res.checks[2].status === 'FAIL', 'Scenario 11: Non-CA asserting keyCertSign fails Basic Constraints check');
}

// Scenario 12: Missing Key Usage or Extended Key Usage
{
  const cert = parseX509Certificate(fixtures.missingKuCertPem);
  const res = validateParsedCertificate(cert);
  assert(res.checks[5].status === 'NOT CHECKED', 'Scenario 12: Missing Key Usage and EKU reports NOT CHECKED limitation');
}

// Scenario 13: Revocation status cannot be checked
{
  const pem = fs.readFileSync(path.join(__dirname, '../certificates/DigiCertGlobalRootG2.pem'), 'utf8');
  const cert = parseX509Certificate(pem);
  const res = validateParsedCertificate(cert);
  assert(res.checks[7].status === 'NOT CHECKED' && res.checks[7].explanation.includes('UNKNOWN'), 'Scenario 13: Revocation status honestly reports NOT CHECKED / UNKNOWN');
}

// Scenario 14: Previously unseen certificate uploaded through Start Analysis
{
  const cert = parseX509Certificate(fixtures.validCustomCertPem);
  assert(cert.subjectCN === 'secure-portal.cloudcorp.io' && cert.keySize === 2048, 'Scenario 14: Previously unseen third-party certificate parsed with genuine attributes');
}

// Scenario 15: The existing six demo certificates and their expected outcomes
{
  const dc = validateParsedCertificate(parseX509Certificate(fs.readFileSync(path.join(__dirname, '../certificates/DigiCertGlobalRootG2.pem'), 'utf8')), { evaluationDate: '2026-10-23' });
  const isrg = validateParsedCertificate(parseX509Certificate(fs.readFileSync(path.join(__dirname, '../certificates/isrgrootx1.pem'), 'utf8')), { evaluationDate: '2026-10-23' });
  const amz = validateParsedCertificate(parseX509Certificate(fs.readFileSync(path.join(__dirname, '../certificates/AmazonRootCA1.pem'), 'utf8')), { evaluationDate: '2026-10-23' });
  const gts = validateParsedCertificate(parseX509Certificate(fs.readFileSync(path.join(__dirname, '../certificates/gtsr1.pem'), 'utf8')), { evaluationDate: '2026-10-23' });
  const ns = validateParsedCertificate(parseX509Certificate(fs.readFileSync(path.join(__dirname, '../certificates/northstar-services.pem'), 'utf8')), { evaluationDate: '2026-10-23' });
  const bp = validateParsedCertificate(parseX509Certificate(fs.readFileSync(path.join(__dirname, '../certificates/bluepeak-gateway.pem'), 'utf8')), { evaluationDate: '2026-10-23', hostnameToVerify: 'gateway.bluepeak.internal' });

  const allExpected = (
    dc.verdict === 'TRUSTED' &&
    isrg.verdict === 'TRUSTED' &&
    amz.verdict === 'TRUSTED' &&
    gts.verdict === 'TRUSTED' &&
    ns.verdict === 'REJECTED' && ns.checks[0].status === 'FAIL' &&
    bp.verdict === 'REJECTED' && bp.checks[4].status === 'FAIL'
  );
  assert(allExpected, 'Scenario 15: All 6 demo certificates produce authentic expected outcomes');
}

console.log('\n================================================================');
console.log(`Results: ${testsPassed} passed, ${testsFailed} failed (Total: ${testsPassed + testsFailed})`);
console.log('================================================================\n');

if (testsFailed > 0) {
  process.exit(1);
}
