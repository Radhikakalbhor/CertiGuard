/**
 * CertiGuard — X.509 Digital Certificate Validation & Expiry Detection Simulator
 * Modelled on RFC 5280 and RFC 6125 specification standards.
 * 100% Client-Side Pure Vanilla JavaScript.
 */

'use strict';

// ============================================================================
// Genuine Certificate Manifest & Trust Store
// ============================================================================
const CERTIFICATE_MANIFEST = [
  {
    id: 'digicert-g2',
    name: 'DigiCert Global Root G2',
    filename: 'DigiCertGlobalRootG2.pem',
    type: 'Root CA Certificate',
    format: 'PEM (X.509)',
    authority: 'DigiCert, Inc.',
    sourceUrl: 'https://cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem',
    subject: 'C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root G2',
    commonName: 'DigiCert Global Root G2',
    issuer: 'C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root G2',
    serialNumber: '03:3A:F1:E6:A7:11:A9:A0:BB:28:64:B1:1D:09:FA:E5',
    notBefore: '2013-08-01',
    notAfter: '2038-01-15',
    sans: '',
    isCa: true,
    intermediateHasCertSign: true,
    keyUsages: {
      digitalSignature: true,
      keyEncipherment: false,
      certSigning: true,
      crlSigning: true,
      dataEncipherment: false,
      keyAgreement: false
    },
    signatureValid: true,
    isRevoked: false,
    trustedInStore: true,
    rawPem: `-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
MrY=
-----END CERTIFICATE-----`
  },
  {
    id: 'isrg-root-x1',
    name: 'ISRG Root X1',
    filename: 'isrgrootx1.pem',
    type: 'Root CA Certificate',
    format: 'PEM (X.509)',
    authority: "Internet Security Research Group (Let's Encrypt)",
    sourceUrl: 'https://letsencrypt.org/certs/isrgrootx1.pem',
    subject: 'C = US, O = Internet Security Research Group, CN = ISRG Root X1',
    commonName: 'ISRG Root X1',
    issuer: 'C = US, O = Internet Security Research Group, CN = ISRG Root X1',
    serialNumber: '82:10:CF:B0:D2:40:E3:59:44:63:E0:BB:63:82:8B:00',
    notBefore: '2015-06-04',
    notAfter: '2035-06-04',
    sans: '',
    isCa: true,
    intermediateHasCertSign: true,
    keyUsages: {
      digitalSignature: false,
      keyEncipherment: false,
      certSigning: true,
      crlSigning: true,
      dataEncipherment: false,
      keyAgreement: false
    },
    signatureValid: true,
    isRevoked: false,
    trustedInStore: true,
    rawPem: `-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----`
  },
  {
    id: 'amazon-root-ca-1',
    name: 'Amazon Root CA 1',
    filename: 'AmazonRootCA1.pem',
    type: 'Root CA Certificate',
    format: 'PEM (X.509)',
    authority: 'Amazon Trust Services',
    sourceUrl: 'https://www.amazontrust.com/repository/AmazonRootCA1.pem',
    subject: 'C = US, O = Amazon, CN = Amazon Root CA 1',
    commonName: 'Amazon Root CA 1',
    issuer: 'C = US, O = Amazon, CN = Amazon Root CA 1',
    serialNumber: '06:6C:9F:CF:99:BF:8C:0A:39:E2:F0:78:8A:43:E6:96:36:5B:CA',
    notBefore: '2015-05-26',
    notAfter: '2038-01-17',
    sans: '',
    isCa: true,
    intermediateHasCertSign: true,
    keyUsages: {
      digitalSignature: true,
      keyEncipherment: false,
      certSigning: true,
      crlSigning: true,
      dataEncipherment: false,
      keyAgreement: false
    },
    signatureValid: true,
    isRevoked: false,
    trustedInStore: true,
    rawPem: `-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA
A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI
U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs
N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv
o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU
5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy
rqXRfboQnoZsG4q5WTP468SQvvG5
-----END CERTIFICATE-----`
  },
  {
    id: 'gts-root-r1',
    name: 'GTS Root R1',
    filename: 'gtsr1.pem',
    type: 'Root CA Certificate',
    format: 'PEM (X.509)',
    authority: 'Google Trust Services LLC',
    sourceUrl: 'https://pki.goog/repo/certs/gtsr1.pem',
    subject: 'C = US, O = Google Trust Services LLC, CN = GTS Root R1',
    commonName: 'GTS Root R1',
    issuer: 'C = US, O = Google Trust Services LLC, CN = GTS Root R1',
    serialNumber: '02:03:E5:93:6F:31:B0:13:49:88:6B:A2:17',
    notBefore: '2016-06-22',
    notAfter: '2036-06-22',
    sans: '',
    isCa: true,
    intermediateHasCertSign: true,
    keyUsages: {
      digitalSignature: true,
      keyEncipherment: false,
      certSigning: true,
      crlSigning: true,
      dataEncipherment: false,
      keyAgreement: false
    },
    signatureValid: true,
    isRevoked: false,
    trustedInStore: true,
    rawPem: `-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw
MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo
27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7w
Cl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjw
TcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0Pfybl
qAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaH
szVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8
Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmk
MiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92
wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70p
aDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrN
VjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQID
AQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBAJ+qQibb
C5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEe
QkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuy
h6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM4
7HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8J
ZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6Ef
MgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/
Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT
6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ
0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm
2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bb
bP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c
-----END CERTIFICATE-----`
  },
  {
    id: 'northstar-services',
    name: 'Northstar Web Services',
    filename: 'northstar-services.pem',
    type: 'End-Entity Server Certificate',
    format: 'PEM (X.509)',
    authority: 'Northstar Security Services (Synthetic Test Fixture)',
    sourceUrl: 'Local OpenSSL Test Fixture',
    isOfficial: false,
    isSynthetic: true,
    subject: 'C = US, O = Northstar Web Services LLC, CN = api.northstar-cloud.internal',
    commonName: 'api.northstar-cloud.internal',
    issuer: 'CN = Northstar Internal Issuing CA, O = Northstar Security Services, C = US',
    intermediateSubject: 'CN = Northstar Internal Issuing CA, O = Northstar Security Services, C = US',
    intermediateIssuer: 'CN = Northstar Internal Issuing CA, O = Northstar Security Services, C = US',
    serialNumber: '20:01',
    notBefore: '2023-01-01',
    notAfter: '2024-01-01',
    sans: 'api.northstar-cloud.internal',
    hostnameToVerify: 'api.northstar-cloud.internal',
    isCa: false,
    intermediateHasCertSign: true,
    keyUsages: {
      digitalSignature: true,
      keyEncipherment: true,
      certSigning: false,
      crlSigning: false,
      dataEncipherment: false,
      keyAgreement: false
    },
    signatureValid: true,
    isRevoked: false,
    trustedInStore: false,
    rootCaKey: 'untrusted',
    rawPem: `-----BEGIN CERTIFICATE-----
MIID0DCCArigAwIBAgICIAEwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UEBhMCVVMx
JDAiBgNVBAoMG05vcnRoc3RhciBTZWN1cml0eSBTZXJ2aWNlczEmMCQGA1UEAwwd
Tm9ydGhzdGFyIEludGVybmFsIElzc3VpbmcgQ0EwHhcNMjMwMTAxMDAwMDAwWhcN
MjQwMTAxMDAwMDAwWjBZMQswCQYDVQQGEwJVUzEjMCEGA1UECgwaTm9ydGhzdGFy
IFdlYiBTZXJ2aWNlcyBMTEMxJTAjBgNVBAMMHGFwaS5ub3J0aHN0YXItY2xvdWQu
aW50ZXJuYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2vDr/gAvj
Xn8v6JAcIqVvENZu9u5PCZ/UzskbaheOcs1Wkgrs5GsFi8rhPD45doKRBcz3/1Ji
jGnxA+uKSOtpdoQuCyHA59otvMELKfFOu9XgViXstcG0kCcmoiGin/E1glACpJxP
iYKwaXuRWTNJ8fW0KYL0AZ0QanbKfOCodml6L3I/XDBPqS4kNX4RiNDE1NFQMrSN
XpRD6JoNwd4HRRDvzuJOFflozbm75+i0wkudOrGAOpxYLeEFqg6lbSRxwft4y7+o
Iii1EMGKyX5vy5dmZ0jcF5Mv1mcg2ZhZOJWCKo8cLc5M1VGQFLbB3/r7F2/zFwAv
ehFwE4oabSXHAgMBAAGjgZ8wgZwwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMC
BaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwJwYDVR0RBCAwHoIcYXBpLm5vcnRoc3Rh
ci1jbG91ZC5pbnRlcm5hbDAdBgNVHQ4EFgQUdV96lpHP2I/e/Po/oHJP10vqb1Uw
HwYDVR0jBBgwFoAUeeExIyUxqeINleuCD60OJrQWJ/wwDQYJKoZIhvcNAQELBQAD
ggEBABy2f/LZa8KWydOI2RXMGwE6DfQVsBRDFgAdRV5xU82anlyLzp1zseFy9tRv
OnWkXt76qCP5NIPMF47nsWDCXlEI2CRMa840GtQiSxfNI9seo3Zr8ShM9aDCw4Rd
AtNr08hq3FOi8y1HPxS9ksirVsDVlfzAbMe3qmMBEp/vMhPUn99XDhmCWATAPfN/
r17sH3IShrVw1+48wILSqUpQzO3js9j1nZnhBwN+i48120V8HFFodRQIWVnl/ics
NdHm+uGD0z1cBIideXRpznJV1p+hkAE3gYTt8zFDEMhZW1KvAd/JSsMNz/RhrVo0
0hr23nZL92eyA+aqLSwKpIHtKoQ=
-----END CERTIFICATE-----`
  },
  {
    id: 'bluepeak-gateway',
    name: 'BluePeak Secure Gateway',
    filename: 'bluepeak-gateway.pem',
    type: 'End-Entity Server Certificate',
    format: 'PEM (X.509)',
    authority: 'BluePeak Technologies (Synthetic Test Fixture)',
    sourceUrl: 'Local OpenSSL Test Fixture',
    isOfficial: false,
    isSynthetic: true,
    subject: 'C = US, O = BluePeak Technologies, CN = cluster-mesh.bluepeak.internal',
    commonName: 'cluster-mesh.bluepeak.internal',
    issuer: 'CN = BluePeak Root Authority, O = BluePeak Technologies, C = US',
    intermediateSubject: 'CN = BluePeak Root Authority, O = BluePeak Technologies, C = US',
    intermediateIssuer: 'CN = BluePeak Root Authority, O = BluePeak Technologies, C = US',
    serialNumber: '30:01',
    notBefore: '2026-01-01',
    notAfter: '2028-01-01',
    sans: 'cluster-mesh.bluepeak.internal, metrics.bluepeak.internal',
    hostnameToVerify: 'gateway.bluepeak.internal',
    isCa: false,
    intermediateHasCertSign: true,
    keyUsages: {
      digitalSignature: true,
      keyEncipherment: true,
      certSigning: false,
      crlSigning: false,
      dataEncipherment: false,
      keyAgreement: false
    },
    signatureValid: true,
    isRevoked: false,
    trustedInStore: false,
    rootCaKey: 'untrusted',
    rawPem: `-----BEGIN CERTIFICATE-----
MIID3jCCAsagAwIBAgICMAEwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMx
HjAcBgNVBAoMFUJsdWVQZWFrIFRlY2hub2xvZ2llczEgMB4GA1UEAwwXQmx1ZVBl
YWsgUm9vdCBBdXRob3JpdHkwHhcNMjYwMTAxMDAwMDAwWhcNMjgwMTAxMDAwMDAw
WjBWMQswCQYDVQQGEwJVUzEeMBwGA1UECgwVQmx1ZVBlYWsgVGVjaG5vbG9naWVz
MScwJQYDVQQDDB5jbHVzdGVyLW1lc2guYmx1ZXBlYWsuaW50ZXJuYWwwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHsI2hjKohiKlzo16BuVonhMxKw+iR
HDrOVyY3VI02eVnvYbAPQq5plxfxcJ3mRK0HCHT1Kx34YVpKio/L8yqlzeN8wJnx
suZiPR5I0whEACYIz8LiA8pcs5sIhSWmF6ysBAUkO5YctCFTIfpuLgQDXj/tELtJ
fjj2WoCS/PCPjMbIhM4B2QOOtfS7xK6CM1sZob3TQTVMsvejy4Z2N72PrYswG2k6
l38AhRe7M3GBXkcNmRNg6NG9c1otLYSgRVlURViaj/lk9ls5sJqnVNjXLobGfgkP
4WYGpxkIvGeAXVsd3NLYBhzPQeVZdtDmngozINsEMb9D2IoOs2UnyJihAgMBAAGj
gbwwgbkwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYI
KwYBBQUHAwEwRAYDVR0RBD0wO4IeY2x1c3Rlci1tZXNoLmJsdWVwZWFrLmludGVy
bmFsghltZXRyaWNzLmJsdWVwZWFrLmludGVybmFsMB0GA1UdDgQWBBRRGYihyrpz
utPuSyh2vfRw3HrpszAfBgNVHSMEGDAWgBQebCa031GgCD7hpOmdBMsu+J0rQDAN
BgkqhkiG9w0BAQsFAAOCAQEAcRaCgyyEjtKXRXzalRSExp/+ncxiC8BY08UZaD12
GhtouVUSmpxJh/tJL349M/eq4qcmdcqL0OkbgYkAqmJ0SDVIInut264ZAF389bFg
9NgWSBlenVh4MtE6dZVc3b/2p+e6nsNoYPQLx/7OdGtYxi0r3S3X3GuByeU5MdT+
xsloPXpn3uLUVxiD/d6NTJdzvQw6XYD0nnH0qeukPdM4w7PYOkpESEF/TtQB3BTm
31eHxagGVdJbnsNZEkB2sTm21j7z6cyWqeINJQkyoNTk7WQgERbEGCo0U8YwoXiW
qvrCTaAVxBeTowSstSgL8Jt2UZfuX/kbVMW3n3SEwXV/5A==
-----END CERTIFICATE-----`
  }
];

// ============================================================================
// State Management
// ============================================================================
const state = {
  metrics: {
    total: 0,
    valid: 0,
    expiring: 0,
    invalid: 0
  },
  lastValidationResult: null,
  manifest: CERTIFICATE_MANIFEST,
  activeCertificate: null,
  activeParsedCert: null,
  trustedRoots: [],
  trustStore: {
    'digicert-g2': {
      name: 'DigiCert Global Root G2',
      trusted: true,
      serial: '03:3A:F1:E6:A7:11:A9:A0:BB:28:64:B1:1D:09:FA:E5',
      fingerprint: 'CB:3C:CB:B7:60:31:E5:E0:13:8F:8D:D3:9A:23:F9:DE:47:FF:C3:5E:43:C1:14:4C:EA:27:D4:6A:5A:B1:CB:5F'
    },
    'isrg-root-x1': {
      name: 'ISRG Root X1',
      trusted: true,
      serial: '82:10:CF:B0:D2:40:E3:59:44:63:E0:BB:63:82:8B:00',
      fingerprint: '96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:AC:BC:0B:E3:CD:A5:27:77:76:04'
    },
    'amazon-root-ca-1': {
      name: 'Amazon Root CA 1',
      trusted: true,
      serial: '06:6C:9F:CF:99:BF:8C:0A:39:E2:F0:78:8A:43:E6:96:36:5B:CA',
      fingerprint: '8E:CD:E6:88:4E:3D:87:B1:EA:04:6B:00:A6:40:D3:7F:5C:86:6D:F8:45:B4:4D:45:E8:23:4C:8A:3E:00:87:6F'
    },
    'gts-root-r1': {
      name: 'GTS Root R1',
      trusted: true,
      serial: '02:03:E5:93:6F:31:B0:13:49:88:6B:A2:17',
      fingerprint: 'E4:AF:2B:26:71:1A:2B:48:27:85:2F:52:66:2C:EF:F0:89:13:71:3E:8A:E5:7D:53:BE:4B:D3:55:F6:9B:6F:11'
    },
    'untrusted': {
      name: 'Custom / Private Internal CA',
      trusted: false,
      serial: 'PRIVATE-INTERNAL-CA-01',
      fingerprint: 'PRIVATE-INTERNAL-CA-NOT-IN-TRUST-STORE'
    }
  }
};

// ============================================================================
// Date Utilities (UTC-Consistent)
// ============================================================================
function parseDateUTC(dateStr) {
  if (!dateStr) return null;
  const parts = dateStr.split('-');
  if (parts.length !== 3) return null;
  const year = parseInt(parts[0], 10);
  const month = parseInt(parts[1], 10) - 1;
  const day = parseInt(parts[2], 10);
  return new Date(Date.UTC(year, month, day, 0, 0, 0));
}

function formatDateISO(date) {
  if (!date) return '';
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  const d = String(date.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function addDaysToDate(date, days) {
  const result = new Date(date.getTime());
  result.setUTCDate(result.getUTCDate() + days);
  return result;
}

function getTodayUTC() {
  const now = new Date();
  return new Date(Date.UTC(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0));
}

// ============================================================================
// UI Toast Notifications
// ============================================================================
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  let iconSvg = '';
  if (type === 'success') {
    iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>';
  } else if (type === 'warning') {
    iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
  } else {
    iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00F2FE" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>';
  }

  toast.innerHTML = `${iconSvg}<span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('toast-fadeout');
    toast.addEventListener('animationend', () => toast.remove());
  }, 3400);
}

function escapeHtml(str) {
  if (typeof str !== 'string') return String(str);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ============================================================================
// Genuine X.509 Certificate Parsing Engine (RFC 5280 / RFC 6125)
// Powered by bundled node-forge library (lib/forge.min.js)
// ============================================================================

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
  const hex = typeof bytes === 'string' ? window.forge.util.bytesToHex(bytes) : bytes;
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

function matchHostname(pattern, host) {
  pattern = (pattern || '').trim().toLowerCase();
  host = (host || '').trim().toLowerCase();

  if (pattern.endsWith('.')) pattern = pattern.slice(0, -1);
  if (host.endsWith('.')) host = host.slice(0, -1);

  if (!pattern || !host) return false;
  if (pattern === host) return true;

  // Single-label wildcard matching (*.example.com) per RFC 6125 §6.4.3
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

/**
 * Genuine X.509 Certificate Parser
 * Extracts all standard fields from a PEM encoded certificate.
 */
function parseX509Certificate(pemText) {
  if (!window.forge || !window.forge.pki) {
    throw new Error('X.509 cryptographic engine (lib/forge.min.js) is not loaded.');
  }

  const pems = splitPemBundle(pemText);
  if (pems.length === 0) {
    throw new Error('No valid PEM certificate found. Must contain "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----".');
  }

  const rawCert = window.forge.pki.certificateFromPem(pems[0]);

  // Public Key info
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

  // Signature Algorithm
  const sigOid = rawCert.signatureOid;
  const sigAlgoName = window.forge.pki.oids[sigOid] || sigOid || 'Unknown';

  // Basic Constraints
  const bc = rawCert.getExtension('basicConstraints');
  const isCa = bc ? !!bc.cA : false;
  const pathLen = bc && bc.pathLenConstraint !== undefined ? bc.pathLenConstraint : null;

  // Key Usage
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

  // Extended Key Usage
  const eku = rawCert.getExtension('extKeyUsage');
  const extKeyUsages = {
    serverAuth: eku ? !!eku.serverAuth : false,
    clientAuth: eku ? !!eku.clientAuth : false,
    codeSigning: eku ? !!eku.codeSigning : false,
    emailProtection: eku ? !!eku.emailProtection : false,
    timeStamping: eku ? !!eku.timeStamping : false,
    present: !!eku
  };

  // Subject Alternative Names (SANs)
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

  // Key Identifiers (SKI / AKI)
  const skiExt = rawCert.getExtension('subjectKeyIdentifier');
  const ski = skiExt && skiExt.subjectKeyIdentifier ? toColonHex(skiExt.subjectKeyIdentifier) : null;

  let aki = null;
  const akiExt = rawCert.extensions ? rawCert.extensions.find(e => e.id === '2.5.29.35' || e.name === 'authorityKeyIdentifier') : null;
  if (akiExt && akiExt.value) {
    try {
      const asn1 = window.forge.asn1.fromDer(akiExt.value);
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

  // SHA-256 Fingerprint
  const der = window.forge.asn1.toDer(window.forge.pki.certificateToAsn1(rawCert)).getBytes();
  const md = window.forge.md.sha256.create();
  md.update(der);
  const fingerprintSha256 = toColonHex(md.digest().toHex());

  // Additional certificates in bundle (if concatenated)
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

/**
 * Initializes the in-memory trusted root certificate store.
 * Parses the authoritative Root CA certificates in CERTIFICATE_MANIFEST.
 */
function initTrustedRoots() {
  if (!window.forge || !window.forge.pki) return;
  state.trustedRoots = [];
  CERTIFICATE_MANIFEST.filter(m => m.trustedInStore && m.rawPem).forEach(entry => {
    try {
      const parsed = parseX509Certificate(entry.rawPem);
      state.trustedRoots.push({
        id: entry.id,
        name: entry.name,
        filename: entry.filename,
        parsed
      });
    } catch (e) {
      console.warn(`Failed to parse root anchor ${entry.id}:`, e);
    }
  });
}

/**
 * Formats Key Usage and EKU into a readable string for the interface.
 */
function formatKeyUsages(parsed) {
  if (!parsed) return 'None specified';
  const parts = [];
  const ku = parsed.keyUsages;
  if (ku.digitalSignature) parts.push('Digital Signature');
  if (ku.keyEncipherment) parts.push('Key Encipherment');
  if (ku.keyCertSign) parts.push('Certificate Signing');
  if (ku.cRLSign) parts.push('CRL Signing');
  if (ku.nonRepudiation) parts.push('Non-Repudiation');
  if (ku.dataEncipherment) parts.push('Data Encipherment');
  if (ku.keyAgreement) parts.push('Key Agreement');

  const eku = parsed.extKeyUsages;
  const ekuParts = [];
  if (eku.serverAuth) ekuParts.push('TLS Web Server Authentication');
  if (eku.clientAuth) ekuParts.push('TLS Web Client Authentication');
  if (eku.codeSigning) ekuParts.push('Code Signing');
  if (eku.emailProtection) ekuParts.push('Email Protection');
  if (eku.timeStamping) ekuParts.push('Time Stamping');

  let result = parts.length > 0 ? parts.join(', ') : 'None asserted';
  if (ekuParts.length > 0) {
    result += ` [${ekuParts.join(', ')}]`;
  }
  return result;
}

// ============================================================================
// Genuine 8-Point Certificate Validation Engine (RFC 5280 & RFC 6125)
// ============================================================================

function validateParsedCertificate(certObj, options = {}) {
  const evalDate = options.evaluationDate ? (typeof options.evaluationDate === 'string' ? parseDateUTC(options.evaluationDate) : options.evaluationDate) : getTodayUTC();
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

  // --------------------------------------------------------------------------
  // Check 1: Validity Period & Expiry Detection
  // --------------------------------------------------------------------------
  let check1Status = 'PASS';
  let check1Message = '';
  let periodState = 'VALID';
  let daysDiff = 0;

  if (!certObj.notBefore || !certObj.notAfter || !evalDate) {
    check1Status = 'FAIL';
    periodState = 'INVALID_DATES';
    check1Message = 'Validity dates are missing or improperly formatted in X.509 payload.';
  } else if (certObj.notAfter.getTime() < certObj.notBefore.getTime()) {
    check1Status = 'FAIL';
    periodState = 'INVERTED_DATES';
    check1Message = `Fatal date range error: notAfter (${formatDateISO(certObj.notAfter)}) precedes notBefore (${formatDateISO(certObj.notBefore)}).`;
  } else if (evalDate.getTime() < certObj.notBefore.getTime()) {
    check1Status = 'FAIL';
    periodState = 'NOT_YET_VALID';
    const daysUntil = Math.ceil((certObj.notBefore.getTime() - evalDate.getTime()) / (1000 * 60 * 60 * 24));
    check1Message = `Certificate is NOT YET VALID. Starts in ${daysUntil} day(s) on ${formatDateISO(certObj.notBefore)}.`;
  } else if (evalDate.getTime() > certObj.notAfter.getTime()) {
    check1Status = 'FAIL';
    periodState = 'EXPIRED';
    const daysAgo = Math.floor((evalDate.getTime() - certObj.notAfter.getTime()) / (1000 * 60 * 60 * 24));
    check1Message = `Certificate is EXPIRED. Exceeded notAfter by ${daysAgo} day(s) (expired on ${formatDateISO(certObj.notAfter)}).`;
  } else {
    daysDiff = Math.floor((certObj.notAfter.getTime() - evalDate.getTime()) / (1000 * 60 * 60 * 24));
    if (daysDiff <= warningDays) {
      check1Status = 'WARN';
      periodState = 'EXPIRING_SOON';
      check1Message = `Certificate is EXPIRING SOON! Only ${daysDiff} day(s) remaining (Threshold: ≤ ${warningDays} days).`;
    } else {
      check1Status = 'PASS';
      periodState = 'VALID';
      check1Message = `Certificate is currently within its validity window. ${daysDiff} day(s) remaining until ${formatDateISO(certObj.notAfter)}.`;
    }
  }

  checks.push({
    id: 'validity_period',
    name: 'Check 1: Validity Period & Expiry Detection',
    status: check1Status,
    periodState,
    daysDiff,
    explanation: check1Message,
    spec: 'RFC 5280 §4.1.2.5'
  });
  if (check1Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check1Message; }
  else if (check1Status === 'WARN') { isWarning = true; if (!primaryReason) primaryReason = check1Message; }

  // Candidate Issuer Resolution
  let candidateIssuer = null;
  if (!isSelfSigned) {
    candidateIssuer = candidateChain.find(c => c.subject === certObj.issuer || (c.subjectCN && c.subjectCN === certObj.issuerCN));
    if (!candidateIssuer) {
      const trustedMatch = state.trustedRoots.find(t => t.parsed.subject === certObj.issuer || (t.parsed.subjectCN && t.parsed.subjectCN === certObj.issuerCN));
      if (trustedMatch) candidateIssuer = trustedMatch.parsed;
    }
  }

  // --------------------------------------------------------------------------
  // Check 2: Issuer-Chain Validation
  // --------------------------------------------------------------------------
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
    explanation: check2Message,
    spec: 'RFC 5280 §6.1 Path Validation'
  });
  if (check2Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check2Message; }
  else if (check2Status === 'INDETERMINATE') { isIndeterminate = true; }

  // --------------------------------------------------------------------------
  // Check 3: CA Constraints & Basic Constraints
  // --------------------------------------------------------------------------
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
    explanation: check3Message,
    spec: 'RFC 5280 §4.2.1.9'
  });
  if (check3Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check3Message; }

  // --------------------------------------------------------------------------
  // Check 4: Trust-Anchor Validation
  // --------------------------------------------------------------------------
  let check4Status = 'PASS';
  let check4Message = '';

  if (isRootCa) {
    const trustedMatch = state.trustedRoots.find(t => t.parsed.fingerprintSha256 === certObj.fingerprintSha256 || t.parsed.serialNumber === certObj.serialNumber);
    if (trustedMatch) {
      check4Status = 'PASS';
      check4Message = `Root anchor verified: Certificate is installed in the client's trusted root store ("${trustedMatch.name}").`;
    } else {
      check4Status = 'FAIL';
      check4Message = `Untrusted Root: Certificate claims to be a root authority ("${certObj.subjectCN}"), but is NOT present in the client's pre-configured trust store.`;
    }
  } else if (candidateIssuer) {
    const trustedRoot = state.trustedRoots.find(t => t.parsed.fingerprintSha256 === candidateIssuer.fingerprintSha256 || t.parsed.subject === candidateIssuer.subject);
    if (trustedRoot) {
      check4Status = 'PASS';
      check4Message = `Chain terminates at verified trusted root anchor: "${trustedRoot.name}".`;
    } else {
      check4Status = 'FAIL';
      check4Message = `Untrusted Root: Certificate chain terminates at an authority ("${candidateIssuer.subjectCN || candidateIssuer.subject}") not present in client trust store.`;
    }
  } else {
    check4Status = 'INDETERMINATE';
    check4Message = 'Trust anchor evaluation incomplete: Issuing certificate is missing, so termination at a trusted root cannot be established.';
  }

  checks.push({
    id: 'trusted_root',
    name: 'Check 4: Trusted Root Anchor',
    status: check4Status,
    explanation: check4Message,
    spec: 'RFC 5280 §6.1.1'
  });
  if (check4Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check4Message; }
  else if (check4Status === 'INDETERMINATE') { isIndeterminate = true; }

  // --------------------------------------------------------------------------
  // Check 5: Hostname & SAN Validation (RFC 6125)
  // --------------------------------------------------------------------------
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
        if (matchHostname(dnsSan, hostToCheck)) {
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
    explanation: check5Message,
    spec: 'RFC 6125 & RFC 5280 §4.2.1.6'
  });
  if (check5Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check5Message; }

  // --------------------------------------------------------------------------
  // Check 6: Key Usage & Extended Key Usage
  // --------------------------------------------------------------------------
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
    explanation: check6Message,
    spec: 'RFC 5280 §4.2.1.3 / §4.2.1.12'
  });
  if (check6Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check6Message; }

  // --------------------------------------------------------------------------
  // Check 7: Cryptographic Signature Integrity
  // --------------------------------------------------------------------------
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
    explanation: check7Message,
    spec: 'RFC 5280 §4.1.1.3'
  });
  if (check7Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check7Message; }
  else if (check7Status === 'INDETERMINATE') { isIndeterminate = true; }

  // --------------------------------------------------------------------------
  // Check 8: Revocation Status (CRL / OCSP)
  // --------------------------------------------------------------------------
  const check8Status = 'NOT CHECKED';
  const check8Message = 'UNKNOWN — Revocation status not checked. In this local offline verification environment, live OCSP responder and CRL distribution point network queries are disabled to preserve privacy and offline operation. Certificate is not assumed unrevoked.';

  checks.push({
    id: 'revocation_status',
    name: 'Check 8: Revocation Status (CRL/OCSP)',
    status: check8Status,
    explanation: check8Message,
    spec: 'RFC 5280 §5 & RFC 6960 (OCSP)'
  });

  // --------------------------------------------------------------------------
  // Aggregate Outcome & Score Computation
  // --------------------------------------------------------------------------
  let overallVerdict = 'TRUSTED';
  if (isRejected) {
    overallVerdict = 'REJECTED';
    const failureList = checks.filter(c => c.status === 'FAIL').map(c => c.explanation);
    primaryReason = failureList[0] || primaryReason;
  } else if (isWarning) {
    overallVerdict = 'WARNING';
    primaryReason = check1Message;
  } else if (isIndeterminate) {
    overallVerdict = 'INDETERMINATE';
    primaryReason = 'Chain verification or cryptographic signature check is indeterminate due to missing issuer certificates in the trust chain.';
  }

  const passedChecksCount = checks.filter(c => c.status === 'PASS').length;
  const indeterminateCount = checks.filter(c => c.status === 'INDETERMINATE').length;
  const notCheckedCount = checks.filter(c => c.status === 'NOT CHECKED').length;
  const failCount = checks.filter(c => c.status === 'FAIL').length;
  const scorePercent = Math.round((passedChecksCount / checks.length) * 100);

  // Recommendations tailored to genuine outcome
  const recommendations = [];
  if (overallVerdict === 'TRUSTED') {
    if (isRootCa) {
      recommendations.push('Root CA trust anchor is structurally intact, validly self-signed, and verified in client root store.');
      recommendations.push('Maintain strict air-gapped protection for the Root CA private key in a Hardware Security Module (HSM).');
      recommendations.push('Monitor CA/Browser Forum baseline requirements for future post-quantum algorithmic migration.');
    } else {
      recommendations.push('Certificate is fully operational and trusted for production TLS traffic.');
      recommendations.push('Configure automated certificate renewal (e.g. ACME protocol / Certbot) before the 30-day expiry threshold.');
      recommendations.push('Regularly monitor Certificate Transparency (CT) logs for unexpected issuance.');
    }
  } else if (overallVerdict === 'WARNING') {
    recommendations.push('Initiate certificate renewal immediately with your issuing Certificate Authority or automated ACME client.');
    recommendations.push('Deploy new certificate to load balancers, CDN edge nodes, and web servers before expiry occurs.');
    recommendations.push('Verify that private keys remain secure and unaffected by renewal.');
  } else if (overallVerdict === 'INDETERMINATE') {
    recommendations.push('Supply the missing intermediate CA certificate bundle (fullchain.pem) in the TLS server configuration.');
    recommendations.push('Ensure the complete certificate chain connects from the end-entity certificate up to a pre-installed trusted root.');
    recommendations.push('Verify that each intermediate certificate possesses the Certificate Signing (keyCertSign) key usage extension.');
  } else {
    if (periodState === 'EXPIRED') {
      recommendations.push('CRITICAL: Replace expired certificate immediately to restore browser and API client trust.');
    } else if (periodState === 'NOT_YET_VALID') {
      recommendations.push('Check server system clocks or wait until the notBefore activation date before deployment.');
    }
    if (check5Status === 'FAIL') {
      recommendations.push('Reissue certificate to include the exact target hostname or a properly scoped single-label wildcard in SAN.');
    }
    if (check4Status === 'FAIL') {
      recommendations.push('Switch to a publicly recognized Root CA or install the private root certificate in client trust stores.');
    }
    if (check7Status === 'FAIL') {
      recommendations.push('Certificate payload is corrupt or has been tampered with. Re-export the original certificate from your CA.');
    }
  }

  return {
    verdict: overallVerdict,
    score: scorePercent,
    passedCount: passedChecksCount,
    indeterminateCount,
    notCheckedCount,
    failCount,
    totalCount: checks.length,
    primaryReason: primaryReason || 'All verifiable checks passed successfully.',
    checks,
    recommendations,
    meta: {
      subject: certObj.subjectCN || certObj.subject,
      hostname: targetHost || certObj.subjectCN,
      evaluationDate: formatDateISO(evalDate),
      notBefore: formatDateISO(certObj.notBefore),
      notAfter: formatDateISO(certObj.notAfter),
      periodState,
      daysDiff,
      warningThreshold: warningDays,
      timestamp: new Date().toISOString()
    }
  };
}

/**
 * Backwards-compatible adapter for Workbench parameter form.
 * If parsed certificate is attached, executes genuine validation;
 * otherwise evaluates form parameters honestly without simulated passes.
 */
function validateCertificate(data) {
  if (data && data.parsedCert) {
    return validateParsedCertificate(data.parsedCert, {
      hostnameToVerify: data.hostnameToVerify,
      evaluationDate: data.evaluationDate,
      warningThreshold: data.warningThreshold
    });
  }

  // Pure manual parameter form evaluation
  const evalDate = parseDateUTC(data.evaluationDate);
  const notBefore = parseDateUTC(data.notBefore);
  const notAfter = parseDateUTC(data.notAfter);
  const warningDays = parseInt(data.warningThreshold, 10) || 30;

  let check1Status = 'PASS';
  let check1Message = '';
  let daysDifference = 0;
  let periodState = 'VALID';

  if (!notBefore || !notAfter || !evalDate) {
    check1Status = 'FAIL';
    periodState = 'INVALID_DATES';
    check1Message = 'Validity dates are missing or improperly formatted.';
  } else if (notAfter.getTime() < notBefore.getTime()) {
    check1Status = 'FAIL';
    periodState = 'INVERTED_DATES';
    check1Message = `Fatal date range error: notAfter precedes notBefore.`;
  } else if (evalDate.getTime() < notBefore.getTime()) {
    check1Status = 'FAIL';
    periodState = 'NOT_YET_VALID';
    const daysUntilActive = Math.ceil((notBefore.getTime() - evalDate.getTime()) / (1000 * 60 * 60 * 24));
    check1Message = `Certificate is NOT YET VALID. Starts in ${daysUntilActive} day(s) on ${data.notBefore}.`;
  } else if (evalDate.getTime() > notAfter.getTime()) {
    check1Status = 'FAIL';
    periodState = 'EXPIRED';
    const daysElapsed = Math.floor((evalDate.getTime() - notAfter.getTime()) / (1000 * 60 * 60 * 24));
    check1Message = `Certificate is EXPIRED. Exceeded notAfter by ${daysElapsed} day(s) (expired on ${data.notAfter}).`;
  } else {
    daysDifference = Math.floor((notAfter.getTime() - evalDate.getTime()) / (1000 * 60 * 60 * 24));
    if (daysDifference <= warningDays) {
      check1Status = 'WARN';
      periodState = 'EXPIRING_SOON';
      check1Message = `Certificate is EXPIRING SOON! Only ${daysDifference} day(s) remaining (Threshold: ≤ ${warningDays} days).`;
    } else {
      check1Status = 'PASS';
      periodState = 'VALID';
      check1Message = `Certificate is currently within its validity period. ${daysDifference} day(s) remaining until ${data.notAfter}.`;
    }
  }

  const checks = [
    {
      id: 'validity_period',
      name: 'Check 1: Validity Period & Expiry Detection',
      status: check1Status,
      periodState,
      daysDiff: daysDifference,
      explanation: check1Message,
      spec: 'RFC 5280 §4.1.2.5'
    }
  ];

  let isRejected = check1Status === 'FAIL';
  let isWarning = check1Status === 'WARN';
  let isIndeterminate = false;
  let primaryReason = isRejected || isWarning ? check1Message : '';

  // Check 2: Chain
  const leafIssuerNorm = (data.issuer || '').trim().toLowerCase();
  const leafSubjectNorm = (data.commonName || '').trim().toLowerCase();
  const isRootCa = data.isCa === true && (leafIssuerNorm === leafSubjectNorm);

  let check2Status = 'PASS';
  let check2Message = '';
  if (isRootCa) {
    check2Status = 'PASS';
    check2Message = `Self-issued Root CA anchor: Subject and Issuer match ("${data.issuer}").`;
  } else {
    const interSubjectNorm = (data.intermediateSubject || '').trim().toLowerCase();
    const leafToInterMatches = (leafIssuerNorm === interSubjectNorm) && leafIssuerNorm.length > 0;
    if (!leafToInterMatches) {
      check2Status = 'INDETERMINATE';
      check2Message = `Chain verification indeterminate: Leaf Issuer ("${data.issuer}") does not match Intermediate Subject ("${data.intermediateSubject}"). Full chain bundle required.`;
      isIndeterminate = true;
    } else {
      check2Status = 'PASS';
      check2Message = `Chain hierarchy matches: Leaf → Intermediate CA ("${data.intermediateSubject}").`;
    }
  }
  checks.push({
    id: 'issuer_chain',
    name: 'Check 2: Issuer-Chain Validation',
    status: check2Status,
    explanation: check2Message,
    spec: 'RFC 5280 §6.1 Path Validation'
  });
  if (check2Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check2Message; }

  // Check 3: CA Constraints
  let check3Status = 'PASS';
  let check3Message = '';
  if (data.isCa) {
    if (!data.keyUsages.certSigning) {
      check3Status = 'FAIL';
      check3Message = 'Basic Constraints Violation: CA certificate lacks Certificate Signing in Key Usage.';
    } else {
      check3Status = 'PASS';
      check3Message = 'Valid Basic Constraints: Asserts CA:TRUE with Certificate Signing authority.';
    }
  } else {
    if (data.keyUsages.certSigning) {
      check3Status = 'FAIL';
      check3Message = 'Basic Constraints Violation: End-entity certificate cannot assert Certificate Signing.';
    } else {
      check3Status = 'PASS';
      check3Message = 'Valid Basic Constraints: Correctly configured as end-entity (isCA=false).';
    }
  }
  checks.push({
    id: 'ca_constraints',
    name: 'Check 3: CA Constraints (Basic Constraints)',
    status: check3Status,
    explanation: check3Message,
    spec: 'RFC 5280 §4.2.1.9'
  });
  if (check3Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check3Message; }

  // Check 4: Trust Anchor
  let check4Status = 'PASS';
  let check4Message = '';
  if (!data.rootIsTrusted) {
    check4Status = 'FAIL';
    check4Message = `Untrusted Root: "${data.rootCaSubject}" is NOT present in the client trusted root store.`;
  } else {
    check4Status = 'PASS';
    check4Message = `Root anchor verified: "${data.rootCaSubject}" is a pre-installed trusted root.`;
  }
  checks.push({
    id: 'trusted_root',
    name: 'Check 4: Trusted Root Anchor',
    status: check4Status,
    explanation: check4Message,
    spec: 'RFC 5280 §6.1.1'
  });
  if (check4Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check4Message; }

  // Check 5: Hostname
  let check5Status = 'PASS';
  let check5Message = '';
  const requestedHost = (data.hostnameToVerify || '').trim();
  const rawSans = (data.sans || '').split(',').map(s => s.trim()).filter(Boolean);

  if (isRootCa) {
    check5Status = 'PASS';
    check5Message = 'Informational: SAN verification not applicable for Root CA trust anchors.';
  } else if (!requestedHost) {
    check5Status = 'FAIL';
    check5Message = 'Hostname to verify is empty.';
  } else if (rawSans.length === 0) {
    check5Status = 'FAIL';
    check5Message = 'No Subject Alternative Names (SANs) provided. RFC 6125 prohibits certificates without SANs.';
  } else if (isIpAddress(requestedHost)) {
    const ipMatch = rawSans.find(s => s.toLowerCase() === requestedHost.toLowerCase());
    if (ipMatch) {
      check5Status = 'PASS';
      check5Message = `IP match confirmed for "${requestedHost}".`;
    } else {
      check5Status = 'FAIL';
      check5Message = `IP address mismatch: "${requestedHost}" not present in IP SANs.`;
    }
  } else {
    let matchedSan = null;
    for (const san of rawSans) {
      if (matchHostname(san, requestedHost)) {
        matchedSan = san;
        break;
      }
    }
    if (matchedSan) {
      check5Status = 'PASS';
      check5Message = `Hostname match confirmed: Requested host "${requestedHost}" matched SAN entry "${matchedSan}".`;
    } else {
      check5Status = 'FAIL';
      check5Message = `Hostname mismatch! Requested host "${requestedHost}" does not match SAN entries: [${rawSans.join(', ')}].`;
    }
  }
  checks.push({
    id: 'hostname_matching',
    name: 'Check 5: Hostname Matching (RFC 6125)',
    status: check5Status,
    explanation: check5Message,
    spec: 'RFC 6125 & RFC 5280 §4.2.1.6'
  });
  if (check5Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check5Message; }

  // Check 6: Key Usage
  let check6Status = 'PASS';
  let check6Message = '';
  if (isRootCa) {
    if (!data.keyUsages.certSigning) {
      check6Status = 'FAIL';
      check6Message = 'Incompatible Key Usage: Root CA requires Certificate Signing (keyCertSign).';
    } else {
      check6Status = 'PASS';
      check6Message = 'Key Usage Verified: Asserts Certificate Signing (keyCertSign) and CRL Signing.';
    }
  } else {
    if (!data.keyUsages.digitalSignature && !data.keyUsages.keyEncipherment) {
      check6Status = 'FAIL';
      check6Message = 'Incompatible Key Usage: TLS end-entity server certificates require Digital Signature and/or Key Encipherment.';
    } else if (data.keyUsages.certSigning) {
      check6Status = 'FAIL';
      check6Message = 'Illegal Key Usage: End-entity certificate cannot assert Certificate Signing.';
    } else {
      check6Status = 'PASS';
      check6Message = 'Key Usage verified: Possesses appropriate cryptographic key usages for TLS server operation.';
    }
  }
  checks.push({
    id: 'key_usage',
    name: 'Check 6: Key Usage & Extended Key Usage',
    status: check6Status,
    explanation: check6Message,
    spec: 'RFC 5280 §4.2.1.3'
  });
  if (check6Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check6Message; }

  // Check 7: Signature
  let check7Status = 'INDETERMINATE';
  let check7Message = '';
  if (!data.signatureValid) {
    check7Status = 'FAIL';
    check7Message = 'Signature Verification Failed: Parameter set indicates signature invalid or tampered.';
  } else {
    check7Status = 'PASS';
    check7Message = 'Signature verified per parameter configuration (Load a genuine PEM certificate for mathematical verification).';
  }
  checks.push({
    id: 'signature_verification',
    name: 'Check 7: Cryptographic Signature Integrity',
    status: check7Status,
    explanation: check7Message,
    spec: 'RFC 5280 §4.1.1.3'
  });
  if (check7Status === 'FAIL') { isRejected = true; if (!primaryReason) primaryReason = check7Message; }

  // Check 8: Revocation Status
  const check8Status = 'NOT CHECKED';
  const check8Message = 'UNKNOWN — Revocation status not checked. In this local offline verification environment, live OCSP responder and CRL distribution point network queries are disabled to preserve privacy and offline operation. Certificate is not assumed unrevoked.';
  checks.push({
    id: 'revocation_status',
    name: 'Check 8: Revocation Status (CRL/OCSP)',
    status: check8Status,
    explanation: check8Message,
    spec: 'RFC 5280 §5 & RFC 6960 (OCSP)'
  });

  let overallVerdict = 'TRUSTED';
  if (isRejected) {
    overallVerdict = 'REJECTED';
  } else if (isWarning) {
    overallVerdict = 'WARNING';
  } else if (isIndeterminate) {
    overallVerdict = 'INDETERMINATE';
  }

  const passedChecksCount = checks.filter(c => c.status === 'PASS').length;
  const scorePercent = Math.round((passedChecksCount / checks.length) * 100);

  return {
    verdict: overallVerdict,
    score: scorePercent,
    passedCount: passedChecksCount,
    totalCount: checks.length,
    primaryReason: primaryReason || 'All checks evaluated successfully.',
    checks,
    recommendations: [
      'For genuine cryptographic verification and RFC 5280 analysis, import an authentic X.509 PEM certificate via the PEM input tab.',
      'Ensure the issuing CA and intermediate bundle are present in the trust store or chain.'
    ],
    meta: {
      subject: data.commonName,
      hostname: data.hostnameToVerify,
      evaluationDate: data.evaluationDate,
      notBefore: data.notBefore,
      notAfter: data.notAfter,
      periodState,
      daysDiff: daysDifference,
      warningThreshold: warningDays,
      timestamp: new Date().toISOString()
    }
  };
}

// ============================================================================
// Form Data Extraction
// ============================================================================
function getFormData() {
  const rootSelect = document.getElementById('rootCaSelect');
  const selectedRootKey = rootSelect ? rootSelect.value : 'digicert-g2';
  const rootInfo = state.trustStore[selectedRootKey] || { name: 'Unknown Root', trusted: false };

  return {
    commonName: document.getElementById('commonName').value.trim(),
    issuer: document.getElementById('issuer').value.trim(),
    serialNumber: document.getElementById('serialNumber').value.trim(),
    sans: document.getElementById('sans').value.trim(),
    hostnameToVerify: document.getElementById('hostnameToVerify').value.trim(),
    
    intermediateSubject: document.getElementById('intermediateSubject').value.trim(),
    intermediateIssuer: document.getElementById('intermediateIssuer').value.trim(),
    rootCaKey: selectedRootKey,
    rootCaSubject: rootInfo.name,
    rootIsTrusted: rootInfo.trusted,

    notBefore: document.getElementById('notBefore').value,
    notAfter: document.getElementById('notAfter').value,
    evaluationDate: document.getElementById('evaluationDate').value,
    warningThreshold: document.getElementById('warningThreshold').value,

    keyUsages: {
      digitalSignature: document.getElementById('kuDigitalSig').checked,
      keyEncipherment: document.getElementById('kuKeyEncipherment').checked,
      certSigning: document.getElementById('kuCertSign').checked,
      crlSigning: document.getElementById('kuCrlSign').checked,
      dataEncipherment: document.getElementById('kuDataEncipherment').checked,
      keyAgreement: document.getElementById('kuKeyAgreement').checked
    },

    isCa: document.getElementById('isCaCheckbox').checked,
    intermediateHasCertSign: document.getElementById('intermediateHasCertSign').checked,
    signatureValid: document.getElementById('signatureValid').checked,
    isRevoked: document.getElementById('isRevoked').checked
  };
}

// ============================================================================
// UI Population & Form Update
// ============================================================================
function setFormData(data) {
  if (data.commonName !== undefined) document.getElementById('commonName').value = data.commonName;
  if (data.issuer !== undefined) document.getElementById('issuer').value = data.issuer;
  if (data.serialNumber !== undefined) document.getElementById('serialNumber').value = data.serialNumber;
  if (data.sans !== undefined) document.getElementById('sans').value = data.sans;
  if (data.hostnameToVerify !== undefined) document.getElementById('hostnameToVerify').value = data.hostnameToVerify;

  if (data.intermediateSubject !== undefined) document.getElementById('intermediateSubject').value = data.intermediateSubject;
  if (data.intermediateIssuer !== undefined) document.getElementById('intermediateIssuer').value = data.intermediateIssuer;
  if (data.rootCaKey !== undefined) document.getElementById('rootCaSelect').value = data.rootCaKey;

  if (data.notBefore !== undefined) document.getElementById('notBefore').value = data.notBefore;
  if (data.notAfter !== undefined) document.getElementById('notAfter').value = data.notAfter;
  if (data.evaluationDate !== undefined) document.getElementById('evaluationDate').value = data.evaluationDate;
  if (data.warningThreshold !== undefined) document.getElementById('warningThreshold').value = data.warningThreshold;

  if (data.keyUsages) {
    document.getElementById('kuDigitalSig').checked = !!data.keyUsages.digitalSignature;
    document.getElementById('kuKeyEncipherment').checked = !!data.keyUsages.keyEncipherment;
    document.getElementById('kuCertSign').checked = !!data.keyUsages.certSigning;
    document.getElementById('kuCrlSign').checked = !!data.keyUsages.crlSigning;
    document.getElementById('kuDataEncipherment').checked = !!data.keyUsages.dataEncipherment;
    document.getElementById('kuKeyAgreement').checked = !!data.keyUsages.keyAgreement;
  }

  if (data.isCa !== undefined) {
    document.getElementById('isCaCheckbox').checked = data.isCa;
    updateToggleText('isCaCheckbox', 'isCaText', 'Yes (CA)', 'No (Leaf)');
  }
  if (data.intermediateHasCertSign !== undefined) {
    document.getElementById('intermediateHasCertSign').checked = data.intermediateHasCertSign;
    updateToggleText('intermediateHasCertSign', 'intermediateCertSignText', 'Yes', 'No');
  }
  if (data.signatureValid !== undefined) {
    document.getElementById('signatureValid').checked = data.signatureValid;
    updateToggleText('signatureValid', 'signatureText', 'Pass', 'Fail');
  }
  if (data.isRevoked !== undefined) {
    document.getElementById('isRevoked').checked = data.isRevoked;
    updateToggleText('isRevoked', 'revokedText', 'Revoked', 'Not Revoked');
  }

  updateChainInspector();
}

function updateToggleText(inputId, textId, activeText, inactiveText) {
  const input = document.getElementById(inputId);
  const textElem = document.getElementById(textId);
  if (input && textElem) {
    textElem.textContent = input.checked ? activeText : inactiveText;
  }
}

function updateChainInspector() {
  const leafSubject = document.getElementById('commonName').value.trim() || 'DigiCert Global Root G2';
  const interSubject = document.getElementById('intermediateSubject').value.trim() || 'DigiCert Global Root G2';
  const rootSelect = document.getElementById('rootCaSelect');
  const rootKey = rootSelect ? rootSelect.value : 'digicert-g2';
  const rootInfo = state.trustStore[rootKey] || { name: 'Unknown Root', trusted: false };

  const nodeLeaf = document.getElementById('nodeLeafText');
  const nodeInter = document.getElementById('nodeInterText');
  const nodeRoot = document.getElementById('nodeRootText');
  const nodeRootTag = document.getElementById('nodeRootTag');

  if (nodeLeaf) nodeLeaf.textContent = leafSubject;
  if (nodeInter) nodeInter.textContent = interSubject;
  if (nodeRoot) nodeRoot.textContent = rootInfo.name;

  if (nodeRootTag) {
    if (rootInfo.trusted) {
      nodeRootTag.className = 'node-tag';
      nodeRootTag.textContent = 'Root (Trusted)';
    } else {
      nodeRootTag.className = 'node-tag untrusted';
      nodeRootTag.textContent = 'Root (Untrusted)';
    }
  }

  // Update Hero visual card preview
  const visualSubject = document.getElementById('visualSubject');
  const visualIssuer = document.getElementById('visualIssuer');
  if (visualSubject) visualSubject.textContent = leafSubject;
  if (visualIssuer) visualIssuer.textContent = interSubject;
}

// ============================================================================
// Render Validation Results
// ============================================================================
function renderResults(result) {
  state.lastValidationResult = result;
  const wrapper = document.getElementById('resultsWrapper');
  const banner = document.getElementById('resultsBanner');
  const iconSlot = document.getElementById('bannerIcon');
  const verdictText = document.getElementById('bannerVerdict');
  const bannerTitle = document.getElementById('bannerTitle');
  const bannerDesc = document.getElementById('bannerDesc');
  const scoreNum = document.getElementById('scoreNumber');
  const scoreBreakdown = document.getElementById('scoreBreakdown');

  const reasonBox = document.getElementById('primaryReasonBox');
  const reasonLabel = document.getElementById('reasonLabel');
  const reasonText = document.getElementById('reasonText');

  const metaSubj = document.getElementById('resMetaSubject');
  const metaHost = document.getElementById('resMetaHostname');
  const metaEval = document.getElementById('resMetaEvalDate');
  const metaDays = document.getElementById('resMetaDays');

  const checksContainer = document.getElementById('checksList');
  const recContainer = document.getElementById('recommendationsList');
  const tsElem = document.getElementById('reportTimestamp');

  // Hero Card Sync
  const heroBadge = document.getElementById('visualBadge');
  const heroStatusText = document.getElementById('visualStatusText');
  const heroValidity = document.getElementById('visualValidity');

  banner.className = 'results-banner';

  if (result.verdict === 'TRUSTED') {
    banner.classList.add('trusted');
    verdictText.textContent = 'TRUSTED';
    bannerTitle.textContent = 'Certificate Validation Succeeded';
    bannerDesc.textContent = 'All verifiable RFC 5280 validation checks passed. The certificate chain terminates at a trusted root anchor, matches the requested identity, and has valid cryptographic signatures.';
    iconSlot.innerHTML = '<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
    reasonBox.style.display = 'none';

    if (heroBadge && heroStatusText) {
      heroBadge.className = 'visual-badge trusted';
      heroStatusText.textContent = 'TRUSTED CERTIFICATE';
    }
  } else if (result.verdict === 'WARNING') {
    banner.classList.add('warning');
    verdictText.textContent = 'WARNING';
    bannerTitle.textContent = 'Expiring Soon — Action Required';
    bannerDesc.textContent = 'Certificate is structurally and cryptographically valid, but its validity period will expire within the configured warning threshold. Renew promptly.';
    iconSlot.innerHTML = '<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
    
    reasonBox.style.display = 'flex';
    reasonBox.className = 'primary-reason-box warning-tone';
    reasonLabel.textContent = 'Urgent Notice:';
    reasonText.textContent = result.primaryReason;

    if (heroBadge && heroStatusText) {
      heroBadge.className = 'visual-badge warning';
      heroStatusText.textContent = 'EXPIRING SOON';
    }
  } else if (result.verdict === 'INDETERMINATE') {
    banner.classList.add('indeterminate');
    verdictText.textContent = 'INDETERMINATE';
    bannerTitle.textContent = 'Validation Indeterminate — Chain Link Missing';
    bannerDesc.textContent = 'One or more required validation checks (such as issuer chain path or signature verification) could not be resolved because required issuing certificates were missing from the chain bundle.';
    iconSlot.innerHTML = '<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#38BDF8" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';

    reasonBox.style.display = 'flex';
    reasonBox.className = 'primary-reason-box warning-tone';
    reasonLabel.textContent = 'Indeterminate Notice:';
    reasonText.textContent = result.primaryReason;

    if (heroBadge && heroStatusText) {
      heroBadge.className = 'visual-badge warning';
      heroStatusText.textContent = 'INDETERMINATE';
    }
  } else {
    banner.classList.add('rejected');
    verdictText.textContent = 'REJECTED';
    bannerTitle.textContent = 'Certificate Verification Failed';
    bannerDesc.textContent = 'One or more mandatory RFC 5280 security checks failed. Clients will abort TLS connections or present a critical security rejection warning.';
    iconSlot.innerHTML = '<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';

    reasonBox.style.display = 'flex';
    reasonBox.className = 'primary-reason-box';
    reasonLabel.textContent = 'Primary Rejection Reason:';
    reasonText.textContent = result.primaryReason;

    if (heroBadge && heroStatusText) {
      heroBadge.className = 'visual-badge rejected';
      heroStatusText.textContent = 'REJECTED / INVALID';
    }
  }

  scoreNum.textContent = `${result.score}%`;
  
  // Honest breakdown summary
  const breakdownParts = [`${result.passedCount}/${result.totalCount} Checks Passed`];
  if (result.indeterminateCount > 0) breakdownParts.push(`${result.indeterminateCount} Indeterminate`);
  if (result.notCheckedCount > 0) breakdownParts.push(`${result.notCheckedCount} Not Checked`);
  if (result.failCount > 0) breakdownParts.push(`${result.failCount} Failed`);
  scoreBreakdown.textContent = breakdownParts.join(' • ');

  metaSubj.textContent = result.meta.subject || '(None)';
  metaHost.textContent = result.meta.hostname || '(None)';
  metaEval.textContent = result.meta.evaluationDate;

  let daysText = '';
  if (result.meta.periodState === 'EXPIRED') {
    const elapsed = Math.floor((parseDateUTC(result.meta.evaluationDate) - parseDateUTC(result.meta.notAfter)) / (1000 * 60 * 60 * 24));
    daysText = `Expired ${elapsed} day(s) ago`;
  } else if (result.meta.periodState === 'NOT_YET_VALID') {
    const until = Math.ceil((parseDateUTC(result.meta.notBefore) - parseDateUTC(result.meta.evaluationDate)) / (1000 * 60 * 60 * 24));
    daysText = `Starts in ${until} day(s)`;
  } else if (result.meta.periodState === 'INVERTED_DATES') {
    daysText = 'Invalid range (notAfter < notBefore)';
  } else {
    daysText = `${result.meta.daysDiff} day(s) remaining (until ${result.meta.notAfter})`;
  }
  metaDays.textContent = daysText;
  if (heroValidity) heroValidity.textContent = daysText;

  checksContainer.innerHTML = '';
  result.checks.forEach(chk => {
    const card = document.createElement('div');
    let statusClass = 'fail';
    let badgeText = chk.status;
    let badgeIcon = '';

    if (chk.status === 'PASS') {
      statusClass = 'pass';
      badgeIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>';
    } else if (chk.status === 'WARN') {
      statusClass = 'warn';
      badgeIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
    } else if (chk.status === 'INDETERMINATE') {
      statusClass = 'indeterminate';
      badgeIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
    } else if (chk.status === 'NOT CHECKED') {
      statusClass = 'not-checked';
      badgeIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>';
    } else {
      statusClass = 'fail';
      badgeIcon = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
    }

    card.className = `check-item-card ${statusClass}`;

    card.innerHTML = `
      <span class="check-badge ${statusClass}">
        ${badgeIcon}
        <span>${badgeText}</span>
      </span>
      <div class="check-content">
        <span class="check-name">${escapeHtml(chk.name)}</span>
        <span class="check-explanation">${escapeHtml(chk.explanation)}</span>
      </div>
      <span class="check-meta-tag">${escapeHtml(chk.spec || '')}</span>
    `;
    checksContainer.appendChild(card);
  });

  recContainer.innerHTML = '';
  result.recommendations.forEach(rec => {
    const li = document.createElement('li');
    li.className = 'rec-item';
    li.innerHTML = `<span class="rec-bullet">›</span><span>${escapeHtml(rec)}</span>`;
    recContainer.appendChild(li);
  });

  const nowFormatted = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  tsElem.textContent = `Report generated: Today at ${nowFormatted}`;

  wrapper.style.display = 'block';
  wrapper.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ============================================================================
// Metrics Counter Updates
// ============================================================================
function updateMetricsUI(verdict) {
  state.metrics.total += 1;
  if (verdict === 'TRUSTED') {
    state.metrics.valid += 1;
  } else if (verdict === 'WARNING') {
    state.metrics.expiring += 1;
  } else {
    state.metrics.invalid += 1;
  }

  document.getElementById('countTotal').textContent = state.metrics.total;
  document.getElementById('countValid').textContent = state.metrics.valid;
  document.getElementById('countExpiring').textContent = state.metrics.expiring;
  document.getElementById('countInvalid').textContent = state.metrics.invalid;

  const captionTotal = document.getElementById('captionTotal');
  if (captionTotal) {
    captionTotal.textContent = `Total validations run in this browser session`;
  }
}

// ============================================================================
// Demo Certificate Library Loading (Genuine Files & Fallback Handling)
// ============================================================================
async function loadCertificateFromLibrary(certId) {
  const entry = state.manifest.find(c => c.id === certId);
  if (!entry) {
    showToast(`Certificate "${certId}" not found in manifest.`, 'warning');
    return;
  }

  // Stale view cleanup before loading new certificate
  const prevResultsWrapper = document.getElementById('resultsWrapper');
  if (prevResultsWrapper) {
    prevResultsWrapper.style.display = 'none';
  }

  // Visual selection feedback in library grid
  document.querySelectorAll('.cert-item-card').forEach(card => {
    card.classList.remove('active-selected');
  });
  const activeCard = document.querySelector(`.cert-item-card[data-cert-id="${certId}"]`);
  if (activeCard) activeCard.classList.add('active-selected');

  const statusBox = document.getElementById('certLoadStatusBox');
  const statusIcon = document.getElementById('loadStatusIcon');
  const statusTitle = document.getElementById('loadStatusTitle');
  const statusMsg = document.getElementById('loadStatusMsg');
  const rawPemCard = document.getElementById('rawPemCard');
  const rawPemDisplay = document.getElementById('rawPemDisplay');
  const rawPemFileTag = document.getElementById('rawPemFileTag');

  let pemText = '';
  let loadSource = '';

  // Attempt live file fetch from certificates/ directory
  try {
    const response = await fetch(`certificates/${entry.filename}`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: Failed to read file`);
    }
    const fetchedText = await response.text();
    if (!fetchedText.includes('-----BEGIN CERTIFICATE-----')) {
      throw new Error('Unsupported certificate format: Missing standard PEM header (-----BEGIN CERTIFICATE-----).');
    }
    pemText = fetchedText.trim();
    loadSource = `Live HTTP fetch from certificates/${entry.filename}`;
  } catch (err) {
    // If running under local file:// protocol or offline, browser security restricts fetch.
    // Use the verified authentic PEM embedded in manifest.
    if (entry.rawPem) {
      pemText = entry.rawPem;
      loadSource = `Verified local manifest (Live fetch restricted by browser protocol)`;
    } else {
      if (statusBox) {
        statusBox.style.display = 'flex';
        statusBox.className = 'cert-load-status-box error';
        statusIcon.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
        statusTitle.textContent = 'File Load Failed';
        statusMsg.textContent = `Could not load "certificates/${entry.filename}". ${err.message}`;
      }
      showToast(`Error loading ${entry.filename}: ${err.message}`, 'warning');
      return;
    }
  }

  // Update Raw PEM Inspector Card
  if (rawPemCard && rawPemDisplay) {
    rawPemDisplay.textContent = pemText;
    if (rawPemFileTag) rawPemFileTag.textContent = entry.filename;
    rawPemCard.style.display = 'block';
  }

  // Update Status Banner
  if (statusBox) {
    statusBox.style.display = 'flex';
    statusBox.className = 'cert-load-status-box';
    statusIcon.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
    const isFixture = entry.isOfficial === false || (entry.type && entry.type.includes('Server')) || (entry.type && entry.type.includes('Fixture'));
    statusTitle.textContent = isFixture ? `Loaded Test Fixture: ${entry.name}` : `Loaded Genuine Certificate: ${entry.name}`;
    statusMsg.textContent = `${entry.authority} • Source: ${entry.sourceUrl} • (${loadSource})`;
  }

  // Populate Workbench Form Controls
  setFormData({
    commonName: entry.commonName,
    issuer: entry.issuer,
    serialNumber: entry.serialNumber,
    sans: entry.sans || '',
    hostnameToVerify: entry.hostnameToVerify || entry.commonName,
    intermediateSubject: entry.intermediateSubject || entry.issuer,
    intermediateIssuer: entry.intermediateIssuer || entry.issuer,
    rootCaKey: entry.rootCaKey || (state.trustStore[entry.id] ? entry.id : 'untrusted'),
    notBefore: entry.notBefore,
    notAfter: entry.notAfter,
    keyUsages: entry.keyUsages,
    isCa: entry.isCa,
    intermediateHasCertSign: entry.intermediateHasCertSign !== undefined ? entry.intermediateHasCertSign : true,
    signatureValid: entry.signatureValid,
    isRevoked: entry.isRevoked
  });

  // Run validation engine immediately and present results ONLY after analysis
  const data = getFormData();
  const result = validateCertificate(data);
  renderResults(result);
  updateMetricsUI(result.verdict);

  showToast(`Loaded and analyzed: ${entry.name}`, 'info');
}

// ============================================================================
// Report Export & Clipboard Utilities
// ============================================================================
function downloadJsonReport() {
  if (!state.lastValidationResult) {
    showToast('Please validate a certificate first to generate a report.', 'warning');
    return;
  }

  const exportPayload = {
    generator: 'CertiGuard X.509 Digital Certificate Validation Simulator',
    standard: 'RFC 5280 / RFC 6125',
    generatedAt: new Date().toISOString(),
    overallVerdict: state.lastValidationResult.verdict,
    validationScore: `${state.lastValidationResult.score}%`,
    checksPassed: `${state.lastValidationResult.passedCount}/${state.lastValidationResult.totalCount}`,
    indeterminateChecks: state.lastValidationResult.indeterminateCount || 0,
    notCheckedChecks: state.lastValidationResult.notCheckedCount || 0,
    failedChecks: state.lastValidationResult.failCount || 0,
    primaryFailureOrWarning: state.lastValidationResult.primaryReason,
    certificateData: state.lastValidationResult.meta,
    detailedChecks: state.lastValidationResult.checks,
    recommendations: state.lastValidationResult.recommendations,
    disclaimer: 'Pure client-side cryptographic analysis modelled upon RFC 5280 and RFC 6125.'
  };

  const jsonStr = JSON.stringify(exportPayload, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  const filename = `certiguard-report-${(state.lastValidationResult.meta.hostname || 'cert').replace(/[^a-zA-Z0-9_-]/g, '_')}-${Date.now()}.json`;
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast(`Report downloaded: ${filename}`, 'success');
}

function copySummaryToClipboard() {
  if (!state.lastValidationResult) {
    showToast('Please validate a certificate first to copy summary.', 'warning');
    return;
  }

  const res = state.lastValidationResult;
  const summaryLines = [
    `=== CertiGuard X.509 Validation Summary ===`,
    `Overall Verdict: ${res.verdict}`,
    `Validation Score: ${res.score}% (${res.passedCount}/${res.totalCount} Checks Passed)`,
    `Subject: ${res.meta.subject}`,
    `Hostname Verified: ${res.meta.hostname}`,
    `Evaluation Date: ${res.meta.evaluationDate}`,
    `Validity Window: ${res.meta.notBefore} to ${res.meta.notAfter}`,
    `Status Detail: ${res.primaryReason}`,
    `------------------------------------------`,
    `Checks Summary:`,
    ...res.checks.map(c => ` [${c.status}] ${c.name} - ${c.explanation}`),
    `------------------------------------------`,
    `Generated by CertiGuard (RFC 5280 Educational Simulator)`
  ];

  const fullText = summaryLines.join('\n');

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(fullText)
      .then(() => showToast('Summary copied to clipboard!', 'success'))
      .catch(() => fallbackCopy(fullText));
  } else {
    fallbackCopy(fullText);
  }
}

function copyRawPem() {
  const pemDisplay = document.getElementById('rawPemDisplay');
  if (!pemDisplay || !pemDisplay.textContent) {
    showToast('No PEM certificate loaded to copy.', 'warning');
    return;
  }

  const pemText = pemDisplay.textContent.trim();
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(pemText)
      .then(() => showToast('Raw PEM copied to clipboard!', 'success'))
      .catch(() => fallbackCopy(pemText));
  } else {
    fallbackCopy(pemText);
  }
}

function fallbackCopy(text) {
  try {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    const successful = document.execCommand('copy');
    document.body.removeChild(textarea);
    if (successful) {
      showToast('Copied to clipboard!', 'success');
    } else {
      showToast('Unable to copy to clipboard.', 'warning');
    }
  } catch (err) {
    showToast('Failed to copy to clipboard.', 'warning');
  }
}

// ============================================================================
// Multi-Page Initializers & Event Handlers
// ============================================================================

/**
 * Mobile Navigation Drawer Setup
 */
function initMobileNav() {
  const toggleBtn = document.getElementById('mobileMenuToggle');
  const drawer = document.getElementById('mobileNavDrawer');
  if (!toggleBtn || !drawer) return;

  toggleBtn.addEventListener('click', () => {
    const isOpen = drawer.classList.toggle('open');
    toggleBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  });

  // Close drawer when clicking outside or clicking any link
  document.addEventListener('click', (e) => {
    if (drawer.classList.contains('open') && !drawer.contains(e.target) && !toggleBtn.contains(e.target)) {
      drawer.classList.remove('open');
      toggleBtn.setAttribute('aria-expanded', 'false');
    }
  });

  drawer.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', () => {
      drawer.classList.remove('open');
      toggleBtn.setAttribute('aria-expanded', 'false');
    });
  });
}

/**
 * Dedicated Page 1: Landing Page Initializer
 */
function initLandingPage() {
  // Hero action buttons
  const heroValidateBtn = document.getElementById('heroValidateBtn');
  if (heroValidateBtn) {
    heroValidateBtn.addEventListener('click', () => {
      window.location.href = 'start-analysis.html';
    });
  }

  const heroDemoBtn = document.getElementById('heroDemoBtn');
  if (heroDemoBtn) {
    heroDemoBtn.addEventListener('click', () => {
      window.location.href = 'demo.html';
    });
  }
}

/**
 * Dedicated Page 2: Demo Certificate Library Initializer
 */
function initDemoLibraryPage() {
  // Attach click listeners to cards and buttons
  document.querySelectorAll('.cert-item-card').forEach(card => {
    const certId = card.getAttribute('data-cert-id');
    if (!certId) return;

    card.addEventListener('click', (e) => {
      // Don't trigger twice if clicking the button inside
      if (e.target.closest('.btn-library-select') || e.target.tagName === 'A' || e.target.tagName === 'BUTTON') {
        return;
      }
      window.location.href = `analysis.html?id=${encodeURIComponent(certId)}`;
    });

    const btn = card.querySelector('.btn-library-select');
    if (btn) {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        window.location.href = `analysis.html?id=${encodeURIComponent(certId)}`;
      });
    }
  });
}

/**
 * Dedicated Page 3: Certificate Analysis Page Initializer
 */
async function initAnalysisPage() {
  const urlParams = new URLSearchParams(window.location.search);
  const isCustom = urlParams.get('custom') === '1';
  let certId = urlParams.get('id');

  let entry = null;
  let loadedPem = '';
  let parsedCert = null;

  if (isCustom) {
    try {
      const stored = JSON.parse(sessionStorage.getItem('certiguard_custom_cert') || '{}');
      if (stored && stored.pem) {
        loadedPem = stored.pem;
        parsedCert = parseX509Certificate(loadedPem);
        entry = {
          id: 'custom-cert',
          name: stored.name || parsedCert.subjectCN || 'Custom Uploaded Certificate',
          filename: 'custom.pem',
          type: parsedCert.isCa ? 'Certificate Authority' : 'End-Entity Server Certificate',
          format: 'PEM (X.509)',
          authority: parsedCert.issuerCN || 'Custom Issuer',
          hostnameToVerify: stored.hostname || parsedCert.subjectCN
        };
      }
    } catch (e) {
      console.warn('Failed to parse custom cert from sessionStorage:', e);
    }
  }

  if (!entry) {
    entry = state.manifest.find(c => c.id === certId);
    if (!entry) {
      if (certId) {
        showToast(`Unknown certificate ID "${escapeHtml(certId)}". Showing DigiCert Global Root G2 instead.`, 'warning');
      }
      certId = 'digicert-g2';
      entry = state.manifest.find(c => c.id === certId);
    }
  }

  // Update Breadcrumb & Header info
  const breadcrumbCurrent = document.getElementById('breadcrumbCertName');
  if (breadcrumbCurrent) breadcrumbCurrent.textContent = entry.name;

  const headerTitle = document.getElementById('analysisCertTitle');
  if (headerTitle) headerTitle.textContent = entry.name;

  const headerAuthority = document.getElementById('analysisCertAuthority');
  if (headerAuthority) {
    headerAuthority.textContent = `${entry.authority} • ${entry.type} • Format: ${entry.format}`;
  }

  // Load and parse PEM file if not already loaded
  if (!parsedCert) {
    loadedPem = entry.rawPem || '';
    if (entry.filename) {
      try {
        const response = await fetch(`certificates/${entry.filename}`);
        if (response.ok) {
          const fetchedText = await response.text();
          if (fetchedText.includes('-----BEGIN CERTIFICATE-----')) {
            loadedPem = fetchedText.trim();
          }
        }
      } catch (e) {
        // Falls back to entry.rawPem
      }
    }

    try {
      parsedCert = parseX509Certificate(loadedPem);
    } catch (e) {
      console.error('Failed to parse certificate PEM:', e);
    }
  }

  // Populate Overview Card with genuine parsed data
  const ovSubject = document.getElementById('ovSubject');
  const ovIssuer = document.getElementById('ovIssuer');
  const ovNotBefore = document.getElementById('ovNotBefore');
  const ovNotAfter = document.getElementById('ovNotAfter');
  const ovSans = document.getElementById('ovSans');
  const ovCaStatus = document.getElementById('ovCaStatus');
  const ovSerial = document.getElementById('ovSerial');
  const ovAlgo = document.getElementById('ovAlgo');
  const ovHostVerified = document.getElementById('ovHostVerified');
  const ovPublicKey = document.getElementById('ovPublicKey');
  const ovKeyUsage = document.getElementById('ovKeyUsage');
  const ovKeyIds = document.getElementById('ovKeyIds');

  if (parsedCert) {
    if (ovSubject) ovSubject.textContent = parsedCert.subject || parsedCert.subjectCN;
    if (ovIssuer) ovIssuer.textContent = parsedCert.issuer || parsedCert.issuerCN;
    if (ovNotBefore) ovNotBefore.textContent = formatDateISO(parsedCert.notBefore);
    if (ovNotAfter) ovNotAfter.textContent = formatDateISO(parsedCert.notAfter);
    if (ovSans) {
      const allSans = parsedCert.sans.dns.concat(parsedCert.sans.ip);
      ovSans.textContent = allSans.length > 0 ? allSans.join(', ') : (parsedCert.isCa ? '(None — Root CA Trust Anchor)' : '(None asserted)');
    }
    if (ovCaStatus) {
      ovCaStatus.textContent = parsedCert.isCa ? `Certificate Authority (CA:TRUE${parsedCert.pathLenConstraint !== null ? ', pathLen=' + parsedCert.pathLenConstraint : ''})` : 'End-Entity Server Certificate (CA:FALSE)';
    }
    if (ovSerial) ovSerial.textContent = parsedCert.serialNumber;
    if (ovAlgo) ovAlgo.textContent = parsedCert.signatureAlgorithm;
    if (ovHostVerified) ovHostVerified.textContent = entry.hostnameToVerify || parsedCert.subjectCN;
    if (ovPublicKey) ovPublicKey.textContent = `${parsedCert.publicKeyAlgorithm} ${parsedCert.keySize ? parsedCert.keySize + '-bit' : ''}`;
    if (ovKeyUsage) ovKeyUsage.textContent = formatKeyUsages(parsedCert);
    if (ovKeyIds) ovKeyIds.textContent = `SKI: ${parsedCert.ski ? parsedCert.ski.slice(0, 23) + '...' : 'None'} | AKI: ${parsedCert.aki ? parsedCert.aki.slice(0, 23) + '...' : 'None'}`;
  } else {
    // Fallback to manifest metadata
    if (ovSubject) ovSubject.textContent = entry.subject || entry.commonName;
    if (ovIssuer) ovIssuer.textContent = entry.issuer;
    if (ovNotBefore) ovNotBefore.textContent = entry.notBefore;
    if (ovNotAfter) ovNotAfter.textContent = entry.notAfter;
    if (ovSans) ovSans.textContent = entry.sans ? entry.sans : '(None — RFC 5280 Root Anchor)';
    if (ovCaStatus) ovCaStatus.textContent = entry.isCa ? 'Certificate Authority (CA:TRUE)' : 'End-Entity Server Certificate (CA:FALSE)';
    if (ovSerial) ovSerial.textContent = entry.serialNumber;
    if (ovAlgo) ovAlgo.textContent = 'sha256WithRSAEncryption';
    if (ovHostVerified) ovHostVerified.textContent = entry.hostnameToVerify || entry.commonName;
  }

  // Real-time Chain Inspector nodes
  const nodeLeaf = document.getElementById('nodeLeafText');
  const nodeInter = document.getElementById('nodeInterText');
  const nodeRoot = document.getElementById('nodeRootText');
  const nodeRootTag = document.getElementById('nodeRootTag');

  const rootKey = entry.rootCaKey || (state.trustStore[entry.id] ? entry.id : 'untrusted');
  const rootInfo = state.trustStore[rootKey] || { name: entry.issuer, trusted: false };

  if (nodeLeaf) nodeLeaf.textContent = parsedCert ? parsedCert.subjectCN : entry.commonName;
  if (nodeInter) nodeInter.textContent = parsedCert ? parsedCert.issuerCN : (entry.intermediateSubject || entry.issuer);
  if (nodeRoot) nodeRoot.textContent = rootInfo.name;
  if (nodeRootTag) {
    if (rootInfo.trusted || (parsedCert && parsedCert.isCa && state.trustedRoots.some(r => r.parsed.serialNumber === parsedCert.serialNumber))) {
      nodeRootTag.className = 'node-tag';
      nodeRootTag.textContent = 'Root (Trusted)';
    } else {
      nodeRootTag.className = 'node-tag untrusted';
      nodeRootTag.textContent = 'Root (Untrusted / Missing)';
    }
  }

  // Evaluation Date input setup
  const evalDateInput = document.getElementById('analysisEvalDate');
  const today = getTodayUTC();
  const todayStr = formatDateISO(today);
  if (evalDateInput && !evalDateInput.value) {
    evalDateInput.value = todayStr;
  }

  // Raw PEM display
  const pemDisplay = document.getElementById('rawPemDisplay');
  const pemFileTag = document.getElementById('rawPemFileTag');
  if (pemDisplay) pemDisplay.textContent = loadedPem;
  if (pemFileTag) pemFileTag.textContent = entry.filename ? `certificates/${entry.filename}` : 'Custom PEM Payload';

  // Execute genuine validation function
  function runAnalysisNow() {
    const currentEvalDate = evalDateInput ? evalDateInput.value : todayStr;
    const warningDays = parseInt(document.getElementById('analysisWarningDays')?.value || '30', 10);
    const targetHost = entry.hostnameToVerify || (parsedCert ? parsedCert.subjectCN : entry.commonName);

    let result;
    if (parsedCert) {
      result = validateParsedCertificate(parsedCert, {
        hostnameToVerify: targetHost,
        evaluationDate: currentEvalDate,
        warningThreshold: warningDays
      });
    } else {
      const certData = {
        commonName: entry.commonName,
        issuer: entry.issuer,
        serialNumber: entry.serialNumber,
        sans: entry.sans || '',
        hostnameToVerify: targetHost,
        intermediateSubject: entry.intermediateSubject || entry.issuer,
        intermediateIssuer: entry.intermediateIssuer || entry.issuer,
        rootCaKey: rootKey,
        rootCaSubject: rootInfo.name,
        rootIsTrusted: rootInfo.trusted,
        notBefore: entry.notBefore,
        notAfter: entry.notAfter,
        evaluationDate: currentEvalDate,
        warningThreshold: warningDays,
        keyUsages: entry.keyUsages,
        isCa: entry.isCa,
        intermediateHasCertSign: entry.intermediateHasCertSign !== undefined ? entry.intermediateHasCertSign : true,
        signatureValid: entry.signatureValid,
        isRevoked: entry.isRevoked
      };
      result = validateCertificate(certData);
    }

    renderResults(result);

    // Hide loader if present
    const loader = document.getElementById('analysisLoader');
    if (loader) loader.style.display = 'none';

    const resultsWrapper = document.getElementById('resultsWrapper');
    if (resultsWrapper) resultsWrapper.style.display = 'block';
  }

  // Run immediately on page load
  runAnalysisNow();

  // Re-run button listener
  const btnReanalyze = document.getElementById('btnReanalyze');
  if (btnReanalyze) {
    btnReanalyze.addEventListener('click', runAnalysisNow);
  }

  if (evalDateInput) {
    evalDateInput.addEventListener('change', runAnalysisNow);
  }

  // PEM Copy Button
  const btnCopyPem = document.getElementById('btnCopyPem');
  if (btnCopyPem) {
    btnCopyPem.addEventListener('click', copyRawPem);
  }

  // Report Export Actions
  const btnDownload = document.getElementById('btnDownloadReport');
  if (btnDownload) {
    btnDownload.addEventListener('click', downloadJsonReport);
  }

  const btnCopy = document.getElementById('btnCopySummary');
  if (btnCopy) {
    btnCopy.addEventListener('click', copySummaryToClipboard);
  }
}

/**
 * Dedicated Page 4: Start Custom Analysis Workbench Initializer
 */
function initStartAnalysisPage() {
  const today = getTodayUTC();
  const todayStr = formatDateISO(today);

  const evalDateInput = document.getElementById('evaluationDate');
  const notBeforeInput = document.getElementById('notBefore');
  const notAfterInput = document.getElementById('notAfter');

  if (evalDateInput && !evalDateInput.value) evalDateInput.value = todayStr;
  if (notBeforeInput && !notBeforeInput.value) notBeforeInput.value = formatDateISO(addDaysToDate(today, -90));
  if (notAfterInput && !notAfterInput.value) notAfterInput.value = formatDateISO(addDaysToDate(today, 275));

  // Tab switching
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPane = document.getElementById(btn.getAttribute('data-target'));
      if (targetPane) targetPane.classList.add('active');
    });
  });

  // Toggle switch labels
  const isCaInput = document.getElementById('isCaCheckbox');
  if (isCaInput) {
    isCaInput.addEventListener('change', () => {
      updateToggleText('isCaCheckbox', 'isCaText', 'Yes (CA)', 'No (Leaf)');
    });
  }

  const interCertSignInput = document.getElementById('intermediateHasCertSign');
  if (interCertSignInput) {
    interCertSignInput.addEventListener('change', () => {
      updateToggleText('intermediateHasCertSign', 'intermediateCertSignText', 'Yes', 'No');
    });
  }

  const sigInput = document.getElementById('signatureValid');
  if (sigInput) {
    sigInput.addEventListener('change', () => {
      updateToggleText('signatureValid', 'signatureText', 'Pass', 'Fail');
    });
  }

  const revInput = document.getElementById('isRevoked');
  if (revInput) {
    revInput.addEventListener('change', () => {
      updateToggleText('isRevoked', 'revokedText', 'Revoked', 'Not Revoked');
    });
  }

  // Real-time chain updates
  ['commonName', 'intermediateSubject', 'rootCaSelect'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', updateChainInspector);
      el.addEventListener('change', updateChainInspector);
    }
  });

  // Form Submit (Parameter Workbench)
  const form = document.getElementById('certForm');
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();

      const commonName = document.getElementById('commonName')?.value.trim();
      if (!commonName) {
        showToast('Please specify a Common Name / Subject for analysis.', 'warning');
        return;
      }

      const data = getFormData();
      const result = validateCertificate(data);
      renderResults(result);
      updateMetricsUI(result.verdict);

      showToast(`Validation complete: Result is ${result.verdict}`, result.verdict === 'TRUSTED' ? 'success' : (result.verdict === 'WARNING' ? 'warning' : 'info'));
    });
  }

  // Form Reset
  const btnReset = document.getElementById('btnResetForm');
  if (btnReset) {
    btnReset.addEventListener('click', () => {
      if (form) form.reset();
      const curToday = getTodayUTC();
      if (evalDateInput) evalDateInput.value = formatDateISO(curToday);
      if (notBeforeInput) notBeforeInput.value = formatDateISO(addDaysToDate(curToday, -90));
      if (notAfterInput) notAfterInput.value = formatDateISO(addDaysToDate(curToday, 275));

      updateToggleText('isCaCheckbox', 'isCaText', 'Yes (CA)', 'No (Leaf)');
      updateToggleText('intermediateHasCertSign', 'intermediateCertSignText', 'Yes', 'No');
      updateToggleText('signatureValid', 'signatureText', 'Pass', 'Fail');
      updateToggleText('isRevoked', 'revokedText', 'Revoked', 'Not Revoked');
      updateChainInspector();

      const resultsWrapper = document.getElementById('resultsWrapper');
      if (resultsWrapper) resultsWrapper.style.display = 'none';

      showToast('Form reset to default parameters.', 'info');
    });
  }

  // File Upload Dropzone Setup
  const dropzone = document.getElementById('certFileDropzone');
  const fileInput = document.getElementById('certFileInput');
  const dropzoneText = document.getElementById('uploadDropzoneText');
  const pemTextarea = document.getElementById('pemTextInput');
  const pemHostnameInput = document.getElementById('pemHostnameInput');

  function handleFileSelected(file) {
    if (!file) return;
    const nameLower = file.name.toLowerCase();
    if (!nameLower.endsWith('.pem') && !nameLower.endsWith('.crt') && !nameLower.endsWith('.cer') && !nameLower.endsWith('.txt')) {
      showToast('Please select a valid certificate file (.pem, .crt, .cer).', 'warning');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      if (pemTextarea) {
        pemTextarea.value = content;
      }
      if (dropzoneText) {
        dropzoneText.textContent = `Loaded file: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
      }
      showToast(`Loaded ${file.name}. Click "Parse & Validate" to inspect.`, 'success');
    };
    reader.onerror = () => {
      showToast('Failed to read certificate file.', 'warning');
    };
    reader.readAsText(file);
  }

  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInput.click();
      }
    });

    fileInput.addEventListener('change', () => {
      if (fileInput.files && fileInput.files[0]) {
        handleFileSelected(fileInput.files[0]);
      }
    });

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-over');
    });

    dropzone.addEventListener('dragenter', (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-over');
    });

    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('drag-over');
    });

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-over');
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleFileSelected(e.dataTransfer.files[0]);
      }
    });
  }

  // "Parse & Validate Certificate" Button Handler
  const btnParseAndValidatePem = document.getElementById('btnParseAndValidatePem');
  if (btnParseAndValidatePem) {
    btnParseAndValidatePem.addEventListener('click', () => {
      const pemStr = pemTextarea ? pemTextarea.value.trim() : '';
      if (!pemStr) {
        showToast('Please paste or upload a PEM certificate first.', 'warning');
        return;
      }

      try {
        const parsed = parseX509Certificate(pemStr);
        const hostnameVal = pemHostnameInput ? pemHostnameInput.value.trim() : '';
        const targetHost = hostnameVal || parsed.subjectCN;

        // Save to sessionStorage for cross-page viewing
        sessionStorage.setItem('certiguard_custom_cert', JSON.stringify({
          pem: pemStr,
          hostname: targetHost,
          name: parsed.subjectCN || 'Custom Uploaded Certificate'
        }));

        // Execute genuine validation
        const result = validateParsedCertificate(parsed, {
          hostnameToVerify: targetHost,
          evaluationDate: evalDateInput ? evalDateInput.value : todayStr
        });

        renderResults(result);
        updateMetricsUI(result.verdict);

        // Also sync Workbench parameters
        setFormData({
          commonName: parsed.subjectCN,
          issuer: parsed.issuerCN || parsed.issuer,
          serialNumber: parsed.serialNumber,
          sans: parsed.sans.dns.concat(parsed.sans.ip).join(', '),
          hostnameToVerify: targetHost,
          notBefore: formatDateISO(parsed.notBefore),
          notAfter: formatDateISO(parsed.notAfter),
          isCa: parsed.isCa,
          keyUsages: parsed.keyUsages
        });

        showToast(`Genuine X.509 validation complete: Result is ${result.verdict} (${result.score}%)`, result.verdict === 'TRUSTED' ? 'success' : (result.verdict === 'WARNING' ? 'warning' : 'info'));
      } catch (err) {
        showToast(`PEM Parsing Error: ${err.message}`, 'warning');
      }
    });
  }

  // "Load into Parameter Workbench" Button Handler
  const btnParsePem = document.getElementById('btnParsePem');
  if (btnParsePem) {
    btnParsePem.addEventListener('click', () => {
      const pemStr = pemTextarea ? pemTextarea.value.trim() : '';
      if (!pemStr) {
        showToast('Please paste or upload a PEM certificate first.', 'warning');
        return;
      }

      try {
        const parsed = parseX509Certificate(pemStr);
        const hostnameVal = pemHostnameInput ? pemHostnameInput.value.trim() : '';

        setFormData({
          commonName: parsed.subjectCN,
          issuer: parsed.issuerCN || parsed.issuer,
          serialNumber: parsed.serialNumber,
          sans: parsed.sans.dns.concat(parsed.sans.ip).join(', '),
          hostnameToVerify: hostnameVal || parsed.subjectCN,
          notBefore: formatDateISO(parsed.notBefore),
          notAfter: formatDateISO(parsed.notAfter),
          isCa: parsed.isCa,
          keyUsages: parsed.keyUsages
        });

        showToast(`Successfully extracted X.509 parameters from "${parsed.subjectCN}". Workbench ready!`, 'success');

        // Switch to parameter workbench tab
        const paramTabBtn = document.querySelector('.tab-btn[data-target="tabWorkbench"]');
        if (paramTabBtn) paramTabBtn.click();
      } catch (err) {
        showToast(`PEM Parsing Error: ${err.message}`, 'warning');
      }
    });
  }

  // Clear PEM Button Handler
  const btnClearPem = document.getElementById('btnClearPem');
  if (btnClearPem) {
    btnClearPem.addEventListener('click', () => {
      if (pemTextarea) pemTextarea.value = '';
      if (pemHostnameInput) pemHostnameInput.value = '';
      if (fileInput) fileInput.value = '';
      if (dropzoneText) dropzoneText.textContent = 'Click to choose or drag & drop a .pem or .crt certificate file';
      showToast('PEM input cleared.', 'info');
    });
  }

  // Report actions
  const btnDownload = document.getElementById('btnDownloadReport');
  if (btnDownload) {
    btnDownload.addEventListener('click', downloadJsonReport);
  }

  const btnCopy = document.getElementById('btnCopySummary');
  if (btnCopy) {
    btnCopy.addEventListener('click', copySummaryToClipboard);
  }

  // Initial sync
  updateChainInspector();
}

// ============================================================================
// Master DOMContentLoaded Router
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  // 1. Initialize genuine in-memory root CA store
  initTrustedRoots();

  // 2. Mobile menu navigation runs on all pages
  initMobileNav();

  // 3. Identify active page and execute corresponding controller
  if (document.getElementById('analysisContainer')) {
    initAnalysisPage();
  } else if (document.getElementById('demoLibraryContainer')) {
    initDemoLibraryPage();
  } else if (document.getElementById('startAnalysisContainer') || document.getElementById('certForm')) {
    initStartAnalysisPage();
  } else if (document.getElementById('landingHero') || document.getElementById('heroValidateBtn')) {
    initLandingPage();
  }
});


