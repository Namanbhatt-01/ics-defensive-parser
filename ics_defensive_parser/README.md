# Multi-Protocol ICS/SCADA Network Compliance Auditor

A modular, lightweight, passive security compliance auditing engine designed to analyze Modbus TCP, DNP3, Siemens S7Comm, and IEC 60870-5-104 (IEC 104) network telemetry logs for operational anomaly detection and regulatory compliance under NCIIPC guidelines.

---

## 📌 Project Overview

Critical Information Infrastructure (CII) assets like electrical grids, water treatment plants, telecom networks, and manufacturing facilities rely on legacy Operational Technology (OT) protocols. Because legacy industrial protocols lack native security (such as encryption or access controls), auditing their telemetry is crucial.

This project is a **Passive Multi-Protocol ICS Log Auditor** designed to parse stored network transaction logs and run them against a configurable compliance baseline definition (`rules.json`). It flags unauthorized operations—such as remote state modifications (Write commands) from unauthorized source IP addresses, malformed protocol headers, or out-of-bounds functions—and maps them directly to the **National Critical Information Infrastructure Protection Centre (NCIIPC)** compliance guidelines.

### Key Features
* 🛡️ **Zero-Network Intrusion:** Completely passive offline parsing with no risk of disrupting delicate PLC/RTU hardware.
* ⚡ **Four-Protocol Support:** Integrated support for:
  * **Modbus TCP:** General automation and sensor telemetry.
  * **DNP3:** Power grid, substation, and water distribution telemetry.
  * **Siemens S7Comm:** Siemens PLC data blocks and state automation.
  * **IEC 60870-5-104 (IEC 104):** Power system transmission grids and telecontrol.
* 🛡️ **Deep Header & Address Anomaly Parsing:** 
  * Checks DNP3 start byte sync headers (`0x0564`).
  * Checks IEC 104 APCI start byte sync headers (`0x68`).
  * Flags control commands directed to network broadcast address endpoints (`255.255.255.255`).
  * Enforces DNP3 function code range bounds validation ($0 \le \text{FC} \le 131$).
* 📋 **Compliance Mapping:** Direct alignment of logged anomalies to NCIIPC Guidelines (e.g., Access Control, Audit Logging, Protocol Validation, Firmware Integrity).
* ⚙️ **Configurable Baselines:** Declarative rules schema allows security operators to easily define authorized engineering workstations.
* 📊 **Audit Trail Generation:** Creates clean, human-readable text logs capturing payload signatures, severity levels, and threat resolutions.

---

## 📁 Repository Structure

```text
ics-defensive-parser/
├── main.py                 # Core compliance analysis script
├── rules.json              # Declarative rules & NCIIPC guideline mapping
├── mock_logs.json          # Mock Modbus, DNP3, S7comm & IEC 104 traffic telemetry
├── audit_report.txt        # Generated compliance audit reports
├── parsers/
│   ├── __init__.py         # Package initialization
│   ├── modbus_parser.py    # Modbus TCP log telemetry extractor
│   ├── dnp3_parser.py      # DNP3 outstation telemetry extractor
│   ├── s7_parser.py        # Siemens S7comm telemetry extractor
│   └── iec104_parser.py    # IEC 104 telecontrol telemetry extractor (NEW)
└── README.md               # Project documentation
```

---

## 🛡️ NCIIPC Compliance Guideline Mapping

Our audit engine evaluates log anomalies using the following compliance mapping framework:

| Event Type / Protocol Code | Severity | Target NCIIPC Control Point | Description & Mitigative Intent |
| :--- | :--- | :--- | :--- |
| **`unauthorized_write_attempt`** | `CRITICAL` | **Sec 6.2 - Access Control & Authorization** | Restricts PLC configuration change rights strictly to defined IP leases or physical workstations. |
| **`authorized_write_activity`** | `INFO` | **Sec 6.4 - Operational Audit Logging** | Maintains a permanent trace of routine administrative updates for configuration management. |
| **`unknown_function_code`** | `WARNING` | **Sec 6.1 - Protocol Validation** | Flags unexpected message types, mitigating buffer overflow exploits or custom command probing. |
| **`dnp3_start_byte_anomaly`** | `CRITICAL` | **Sec 6.1 - Protocol Validation** | Flags frames lacking DNP3 `0x0564` sync headers, which indicate fuzzed payloads or telemetry corruption. |
| **`iec104_start_byte_anomaly`** | `CRITICAL` | **Sec 6.1 - Protocol Validation** | Flags frames lacking IEC 104 `0x68` sync headers, which indicate malformed transport frames. |
| **`dnp3_broadcast_anomaly`** | `CRITICAL` | **Sec 6.1 - Protocol Validation** | Flags commands sent to broadcast targets (`255.255.255.255`), which bypass security boundaries. |
| **`DNP3 - 27 (Delete File)`** | `CRITICAL` | **Sec 6.2 - Access Control & Authorization** | Monitors remote operations attempting file deletions on the outstation filesystem. |
| **`S7comm - 26 (Download)`** | `CRITICAL` | **Sec 6.3 - Firmware Integrity** | Audits firmware updates or block code downloads to maintain PLC memory integrity. |
| **`S7comm - 41 (PLC Stop)`** | `CRITICAL` | **Sec 6.2 - Access Control & Authorization** | Flags STOP requests that halt PLC program loops and shut down physical processes. |
| **`IEC104 - 46 (Double Command)`** | `CRITICAL` | **Sec 6.2 - Access Control & Authorization** | Logs and validates Double Commands (Type ID 46) executed to open/close transmission lines. |

---

## ⚙️ How It Works

1. **Extraction:** `main.py` detects the protocol from incoming telemetry logs (`mock_logs.json`) and routes them to the correct parser module under `parsers/`.
2. **Pre-Validation Checks:** For protocols like DNP3 and IEC 104, the engine runs deep header sanity checks:
   * Validates DNP3 sync frames (`0x0564`).
   * Validates IEC 104 sync frames (`0x68`).
   * Validates broadcast destination boundaries.
   * Validates function code ranges.
3. **Access Control Check:** If a valid control update (Write, PLC Stop, configuration edit, ASDU Command) is detected, the engine matches the source IP against the authorized list (`authorized_engineering_workstations` in `rules.json`).
4. **Reporting:** Anomalies are printed in real-time to stdout and appended to a persistent audit ledger `audit_report.txt`.

---

## 🚀 Getting Started

### Prerequisites
* Python 3.x (No third-party packages required; utilizes standard library)

### Execution
Run the auditor engine from the repository root:
```bash
python3 main.py
```

### Example Console Output
```text
=====================================================================================
       PASSIVE ICS/SCADA MULTI-PROTOCOL COMPLIANCE AUDITING ENGINE       
   [ Protocols: Modbus TCP | DNP3 | Siemens S7Comm | IEC 60870-5-104 (IEC 104) ]   
=====================================================================================
[*] Loading compliance guidelines from: ./rules.json
[*] Loading network traffic logs from: ./mock_logs.json
[*] Analyzing 23 network traffic log entries...
[*] INFO Protocol: ModbusTCP | IP: 192.168.1.100 | NCIIPC: Sec 6.4 - Operational Audit Logging
[!] CRITICAL Protocol: DNP3 | IP: 192.168.1.99 | NCIIPC: Sec 6.1 - Protocol Validation
[!] CRITICAL Protocol: DNP3 | IP: 192.168.1.50 | NCIIPC: Sec 6.1 - Protocol Validation
[!] CRITICAL Protocol: IEC104 | IP: 192.168.1.222 | NCIIPC: Sec 6.1 - Protocol Validation
[!] CRITICAL Protocol: ModbusTCP | IP: 192.168.1.215 | NCIIPC: Sec 6.2 - Access Control & Authorization
[!] CRITICAL Protocol: DNP3 | IP: 192.168.1.215 | NCIIPC: Sec 6.2 - Access Control & Authorization
[!] CRITICAL Protocol: IEC104 | IP: 192.168.1.215 | NCIIPC: Sec 6.2 - Access Control & Authorization
[!] CRITICAL Protocol: S7Comm | IP: 192.168.1.215 | NCIIPC: Sec 6.2 - Access Control & Authorization
=====================================================================================
[+] Compliance scan complete. Warnings flagged: 13
[+] Comprehensive report written to: ./audit_report.txt
=====================================================================================
```
