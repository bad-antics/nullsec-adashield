# NullSec AdaShield

**Cryptographic Protocol Validator** written in Ada 2012

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/bad-antics/nullsec-adashield/releases)
[![Language](https://img.shields.io/badge/language-Ada%202012-02599C.svg)](https://www.adaic.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Part of the **NullSec** offensive security toolkit  
> Twitter: [x.com/AnonAntics](https://x.com/AnonAntics)  
> Portal: [bad-antics.github.io](https://bad-antics.github.io)

## Overview

AdaShield is a cryptographic protocol validator that audits TLS/SSL, SSH, and IPSec configurations for security vulnerabilities. Built with Ada's strong typing, contract-based programming, and compile-time safety guarantees.

## Ada 2012 Features Showcased

- **Strong Typing**: Constrained ranges and enumerations
- **Design by Contract**: Pre/Post conditions
- **Static Predicates**: Compile-time constraints
- **Discriminated Records**: Type-safe variants
- **Generic Containers**: Type-safe collections
- **Expression Functions**: Inline predicates
- **Aspect Specifications**: Inline, Pre, Post

## Supported Protocols

| Protocol | Status | Detection |
|----------|--------|-----------|
| TLS 1.0 | Deprecated | ✅ |
| TLS 1.1 | Deprecated | ✅ |
| TLS 1.2 | Current | ✅ |
| TLS 1.3 | Modern | ✅ |
| SSL 3.0 | Deprecated | ✅ |
| SSH 1 | Deprecated | ✅ |
| SSH 2 | Current | ✅ |
| IPSec IKEv1 | Legacy | ✅ |
| IPSec IKEv2 | Current | ✅ |

## Vulnerability Detection

| Type | Severity | MITRE |
|------|----------|-------|
| Weak Protocol | HIGH | T1557 |
| Deprecated Cipher | HIGH | T1040 |
| Small Key Size | MEDIUM | T1588.004 |
| No Forward Secrecy | MEDIUM | T1557 |
| Certificate Issues | MEDIUM | T1553 |
| Misconfiguration | LOW | T1562 |

## Installation

```bash
# Clone
git clone https://github.com/bad-antics/nullsec-adashield.git
cd nullsec-adashield

# Build with GNAT
gnatmake -gnat2012 -O2 adashield.adb

# Or with GPRbuild
gprbuild -P adashield.gpr
```

## Usage

```bash
# Run demo mode
./adashield

# Scan specific host
./adashield -h example.com -p 443

# Check certificate
./adashield --cert server.pem

# Verbose output
./adashield -v -h example.com
```

### Options

```
USAGE:
    adashield [OPTIONS]

OPTIONS:
    -h, --host       Target host to scan
    -p, --port       Target port (default: 443)
    --cert           Certificate file to analyze
    -v, --verbose    Verbose output
    --json           JSON output format
```

## Sample Output

```
╔══════════════════════════════════════════════════════════════════╗
║         NullSec AdaShield - Cryptographic Protocol Validator     ║
╚══════════════════════════════════════════════════════════════════╝

[Demo Mode]

Scanning cryptographic protocol configurations...

  Loaded 7 protocol configurations

Validating protocols against security policies...

  Checking: TLS_1_0 with DES_EDE3_CBC
  Checking: TLS_1_1 with AES_128_CBC
  Checking: TLS_1_2 with RC4_128
  Checking: TLS_1_3 with AES_256_GCM
  Checking: SSH_1 with DES_CBC
  Checking: SSH_2 with CHACHA20_POLY1305
  Checking: IPSEC_IKEV1 with DES_EDE3_CBC

═══════════════════════════════════════════════════════════════════
                         FINDINGS
═══════════════════════════════════════════════════════════════════

  [HIGH]     Deprecated protocol: TLS_1_0
    Type:        WEAK_PROTOCOL
    Risk Score:  95/100
    MITRE:       T1557
    Remediation: Upgrade to TLS 1.2 or TLS 1.3

  [HIGH]     Weak cipher suite: DES_EDE3_CBC
    Type:        DEPRECATED_CIPHER
    Risk Score:  35/100
    MITRE:       T1040
    Remediation: Use AES-256-GCM or ChaCha20-Poly1305

  [MEDIUM]   Insufficient key size: 1024 bits
    Type:        SMALL_KEY_SIZE
    Risk Score:  25/100
    MITRE:       T1588.004
    Remediation: Use minimum 2048-bit keys, prefer 4096-bit

═══════════════════════════════════════════════════════════════════

  Summary:
    Total Findings:  15
    Critical:        0
    High:            8
    Medium:          7
    Low:             0
    Aggregate Risk:  285/400
```

## Code Highlights

### Strong Typing with Constrained Ranges
```ada
type Protocol_Version is range 1 .. 5;
type Key_Size is range 128 .. 4096;
type Risk_Score is delta 0.01 range 0.0 .. 100.0;
```

### Static Predicates (Compile-time Constraints)
```ada
subtype Strong_Key_Size is Key_Size
  with Static_Predicate => Strong_Key_Size >= 2048;

subtype Modern_Protocol is Protocol_Type
  with Static_Predicate => Modern_Protocol in TLS_1_2 | TLS_1_3 | SSH_2;

subtype Weak_Cipher is Cipher_Suite
  with Static_Predicate => Weak_Cipher in DES_CBC | RC4_128 | RSA_1024;
```

### Design by Contract
```ada
function Calculate_Risk (
   Proto : Protocol_Type;
   Ciph  : Cipher_Suite;
   Bits  : Key_Size
) return Risk_Score
with
   Pre  => Bits >= 128,
   Post => Calculate_Risk'Result >= 0.0 and Calculate_Risk'Result <= 100.0;
```

### Expression Functions
```ada
function Is_Protocol_Deprecated (Proto : Protocol_Type) return Boolean is
  (Proto in SSL_3_0 | TLS_1_0 | TLS_1_1 | SSH_1 | IPSec_IKEv1)
with Inline;

function Supports_PFS (KX : Cipher_Suite) return Boolean is
  (KX in ECDHE_P256 | ECDHE_P384 | ECDHE_X25519)
with Inline;
```

### Generic Container Instantiation
```ada
package Finding_Vectors is new Ada.Containers.Vectors
  (Index_Type   => Natural,
   Element_Type => Finding);
```

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                 AdaShield Architecture                         │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│   ┌──────────────────┐                                        │
│   │  Protocol Config │  (TLS, SSH, IPSec)                     │
│   │  Strong Types    │  Constrained ranges                    │
│   └────────┬─────────┘                                        │
│            │                                                   │
│            ▼                                                   │
│   ┌──────────────────────────────────────────────────┐        │
│   │             Validation Engine                     │        │
│   │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │        │
│   │  │ Protocol    │ │ Cipher      │ │ Key Size    │ │        │
│   │  │ Check       │ │ Check       │ │ Check       │ │        │
│   │  └─────────────┘ └─────────────┘ └─────────────┘ │        │
│   │         Pre/Post Contracts                        │        │
│   └────────────────────────┬─────────────────────────┘        │
│                            │                                   │
│                            ▼                                   │
│   ┌──────────────────┐    ┌──────────────────┐               │
│   │  Static          │    │  Finding         │               │
│   │  Predicates      │───▶│  Vector          │               │
│   │  (Compile-time)  │    │  (Generic)       │               │
│   └──────────────────┘    └────────┬─────────┘               │
│                                    │                          │
│                                    ▼                          │
│                           ┌──────────────────┐               │
│                           │  Risk Score      │               │
│                           │  Calculation     │               │
│                           │  (delta type)    │               │
│                           └──────────────────┘               │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## Why Ada?

| Requirement | Ada Advantage |
|-------------|---------------|
| Correctness | Design by contract |
| Safety | Strong static typing |
| Reliability | Compile-time checks |
| Security | Range constraints |
| Maintainability | Explicit interfaces |
| Performance | Zero-cost abstractions |

## License

MIT License - See [LICENSE](LICENSE) for details.

## Related Tools

- [nullsec-cryptoaudit](https://github.com/bad-antics/nullsec-cryptoaudit) - Crypto auditor (Scala)
- [nullsec-cppsentry](https://github.com/bad-antics/nullsec-cppsentry) - Packet sentinel (C++)
- [nullsec-zigscan](https://github.com/bad-antics/nullsec-zigscan) - Binary analyzer (Zig)
