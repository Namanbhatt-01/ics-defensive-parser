#!/usr/bin/env python3
"""
Passive Multi-Protocol ICS Network Compliance Auditing Engine
Integrates defensive validation logic for Modbus TCP, DNP3, Siemens S7Comm, and IEC 60870-5-104 (IEC 104).
Maps anomalous control actions, protocol validation issues, and network anomalies
directly to CII compliance guidelines and calculates operational risk scores.
"""

import json
import os
import sys
import re
import argparse
from datetime import datetime

# Severity level mapping to filter logs during compliance audits
SEVERITY_LEVELS = {
    "INFO": 1,
    "WARNING": 2,
    "CRITICAL": 3
}

# Insert directory into path to ensure parsers and utils package are importable
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE_DIR = os.path.dirname(BASE_DIR)
sys.path.insert(0, BASE_DIR)

try:
    from utils import is_valid_ipv4, is_valid_hex_payload
    from parsers.modbus_parser import parse_modbus_log
    from parsers.dnp3_parser import parse_dnp3_log
    from parsers.s7_parser import parse_s7_log
    from parsers.iec104_parser import parse_iec104_log
except ImportError as e:
    # Fail-safe termination: Sanitized error reporting without system stack tracing
    print(f"[-] Internal Error: Critical components failed to load. Details: {e}", file=sys.stderr)
    sys.exit(1)

def load_json_file(file_path):
    """Loads a JSON file safely. Sanitizes error outputs to prevent path/system details leaks."""
    if not os.path.exists(file_path):
        print(f"[-] Critical: Required file is missing at {file_path}", file=sys.stderr)
        sys.exit(1)
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"[-] Critical: Failed to parse {file_path}. Invalid file structure.", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print(f"[-] Critical: An unexpected system read error occurred for {file_path}", file=sys.stderr)
        sys.exit(1)

def calculate_threat_level(score):
    """Maps a numerical threat score to an CII operational threat level category."""
    if score <= 15:
        return "LOW", "Nominal Operational Baseline"
    elif score <= 40:
        return "MEDIUM", "Minor Log Anomalies Detected"
    elif score <= 75:
        return "HIGH", "Unauthorized ICS Operations Flagged"
    else:
        return "CRITICAL", "Potential Cyber-Physical Attack Underway"

def main():
    # Setup command line interface arguments
    parser = argparse.ArgumentParser(description="Multi-Protocol ICS Passive Compliance Auditing Engine")
    parser.add_argument("-r", "--rules", default=os.path.join(WORKSPACE_DIR, "data", "rules.json"), help="Path to rules.json")
    parser.add_argument("-l", "--logs", default=os.path.join(WORKSPACE_DIR, "data", "mock_logs.json"), help="Path to mock_logs.json")
    parser.add_argument("-v", "--level", choices=["INFO", "WARNING", "CRITICAL"], help="Minimum log severity level to audit")
    
    args = parser.parse_args()

    # Securely load configuration rules and logs
    rules = load_json_file(args.rules)
    logs = load_json_file(args.logs)
    
    # Configure logging threshold limit
    config_threshold = args.level or rules.get("system_config", {}).get("default_logging_threshold", "INFO")
    threshold_weight = SEVERITY_LEVELS.get(config_threshold, 1)
    
    auth_ips = rules.get("authorized_engineering_workstations", [])
    risk_weights = rules.get("system_config", {}).get("risk_scoring_weights", {})
    
    warnings_found = 0
    total_logs = len(logs)
    audit_entries = []
    
    # Threat score calculation variables
    accumulated_threat_score = 0
    
    audit_report_path = os.path.join(WORKSPACE_DIR, "audit_report.txt")
    
    # Initialize/Reset audit report file safely
    try:
        with open(audit_report_path, 'w') as report:
            report.write("=" * 85 + "\n")
            report.write("               CII ICS MULTI-PROTOCOL COMPLIANCE REPORT               \n")
            report.write(f"Generated on : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            report.write("Scope        : Passive Modbus TCP, DNP3, Siemens S7comm, and IEC 104 Baseline Audit\n")
            report.write(f"Filter Level : {config_threshold} and higher\n")
            report.write("=" * 85 + "\n\n")
    except Exception:
        print("[-] Critical: Unable to write audit report to disk. Check directory permissions.", file=sys.stderr)
        sys.exit(1)
        
    print("=" * 85)
    print("       PASSIVE ICS/SCADA MULTI-PROTOCOL COMPLIANCE AUDITING ENGINE       ")
    print("   [ Protocols: Modbus TCP | DNP3 | Siemens S7Comm | IEC 60870-5-104 (IEC 104) ]   ")
    print("=" * 85)
    print(f"[*] Audit Severity Filter: {config_threshold} (Only recording events of level {config_threshold} or higher)")
    print(f"[*] Analyzing {total_logs} network traffic log entries...")
    
    for idx, entry in enumerate(logs, 1):
        protocol = entry.get("protocol", "UNKNOWN")
        alert = None
        parsed = {}
        comp_map = {}
        
        # Extract and validate source/destination IPs to mitigate IP spoofing/validation bypass
        src_ip = entry.get("source_ip", "UNKNOWN")
        dst_ip = entry.get("destination_ip", "UNKNOWN")
        payload = entry.get("payload", "")
        
        if not is_valid_ipv4(src_ip) or not is_valid_ipv4(dst_ip):
            alert = {
                "type": "invalid_ip_anomaly",
                "details": f"CRITICAL: Non-compliant IPv4 address structure detected (Source: '{src_ip}' | Destination: '{dst_ip}')."
            }
            comp_map = {
                "invalid_ip_anomaly": {
                    "severity": "CRITICAL",
                    "cii_control": "Sec 6.1 - Protocol Validation",
                    "description": "Network telemetry log contains malformed IP address headers. Violates basic IP routing guidelines."
                }
            }
            warnings_found += 1
            parsed = {
                "protocol": protocol,
                "timestamp": entry.get("timestamp", datetime.now().isoformat()),
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "payload": payload,
                "notes": entry.get("notes", "Malformed IP header metadata.")
            }
            
        elif not is_valid_hex_payload(payload):
            alert = {
                "type": "malformed_payload_anomaly",
                "details": "CRITICAL: Non-hexadecimal characters detected in binary payload field."
            }
            comp_map = {
                "malformed_payload_anomaly": {
                    "severity": "CRITICAL",
                    "cii_control": "Sec 6.1 - Protocol Validation",
                    "description": "Binary payload contains non-hex characters. Indicates potential frame injection or log corruption."
                }
            }
            warnings_found += 1
            parsed = {
                "protocol": protocol,
                "timestamp": entry.get("timestamp", datetime.now().isoformat()),
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "payload": payload,
                "notes": entry.get("notes", "Hex validation check failed.")
            }
            
        # 1. Modbus TCP Protocol Validation and Auditing
        elif protocol == "ModbusTCP":
            parsed = parse_modbus_log(entry)
            proto_rules = rules.get("Modbus", {})
            func_code = parsed.get("function_code", 0)
            
            try:
                func_code = int(func_code)
            except (ValueError, TypeError):
                func_code = -1
                
            allowed_reads = proto_rules.get("allowed_read_function_codes", [])
            monitored_writes = proto_rules.get("monitored_write_function_codes", [])
            comp_map = proto_rules.get("compliance_mapping", {})
            
            is_write = func_code in monitored_writes
            is_read = func_code in allowed_reads
            
            if is_write:
                if parsed["source_ip"] in auth_ips:
                    alert = {
                        "type": "authorized_write_activity",
                        "details": f"Authorized Modbus register write (FC: {func_code}) executed on Unit ID {parsed.get('unit_id')} from workstation {parsed['source_ip']}."
                    }
                else:
                    alert = {
                        "type": "unauthorized_write_attempt",
                        "details": f"CRITICAL: Unauthorized Modbus write (FC: {func_code}) attempted on Unit ID {parsed.get('unit_id')} from non-workstation IP {parsed['source_ip']}."
                    }
                    warnings_found += 1
            elif is_read and str(func_code) in comp_map:
                alert = {
                    "type": str(func_code),
                    "details": f"Modbus administrative action ({comp_map[str(func_code)]['name']}) performed from source IP {parsed['source_ip']}."
                }
            elif not is_read and not is_write:
                alert = {
                    "type": "unknown_function_code",
                    "details": f"WARNING: Unknown Modbus function code {func_code} detected from source IP {parsed['source_ip']}."
                }
                warnings_found += 1
                
        # 2. DNP3 Protocol Validation and Auditing
        elif protocol == "DNP3":
            parsed = parse_dnp3_log(entry)
            proto_rules = rules.get("DNP3", {})
            func_code = parsed.get("function_code", 0)
            
            try:
                func_code = int(func_code)
            except (ValueError, TypeError):
                func_code = -1
                
            payload = parsed.get("payload", "")
            dest_ip = parsed.get("destination_ip", "")
            comp_map = proto_rules.get("compliance_mapping", {})
            
            # Anomaly A: Start Byte Verification (Sync sequence 0x0564 check)
            if payload and not payload.lower().startswith("0564"):
                alert = {
                    "type": "dnp3_start_byte_anomaly",
                    "details": "CRITICAL: Malformed DNP3 packet missing valid start bytes sync pattern (0x0564)."
                }
                comp_map["dnp3_start_byte_anomaly"] = {
                    "severity": "CRITICAL",
                    "cii_control": "Sec 6.1 - Protocol Validation",
                    "description": "DNP3 frame lacks 0x0564 sync headers, indicative of packet corruption or scanning anomalies."
                }
                warnings_found += 1
            # Anomaly B: Broadcast Destination Address Abuse
            elif dest_ip == "255.255.255.255":
                alert = {
                    "type": "dnp3_broadcast_anomaly",
                    "details": f"CRITICAL: DNP3 command directed to broadcast destination 255.255.255.255 from source IP {parsed['source_ip']}."
                }
                comp_map["dnp3_broadcast_anomaly"] = {
                    "severity": "CRITICAL",
                    "cii_control": "Sec 6.1 - Protocol Validation",
                    "description": "Control messages directed to broadcast endpoints violates segment containment guidelines."
                }
                warnings_found += 1
            # Anomaly C: Invalid Function Code Bounds Check (FUNC_CODE < 0 or FUNC_CODE > 131)
            elif func_code < 0 or func_code > 131:
                alert = {
                    "type": "dnp3_func_code_anomaly",
                    "details": f"CRITICAL: Out-of-bounds DNP3 function code {func_code} detected in network logs."
                }
                comp_map["dnp3_func_code_anomaly"] = {
                    "severity": "CRITICAL",
                    "cii_control": "Sec 6.1 - Protocol Validation",
                    "description": "DNP3 function code value lies outside standardized definitions (0-131)."
                }
                warnings_found += 1
            else:
                allowed_reads = proto_rules.get("allowed_read_function_codes", [])
                monitored_writes = proto_rules.get("monitored_write_function_codes", [])
                
                is_write = func_code in monitored_writes
                is_read = func_code in allowed_reads
                
                func_code_str = str(func_code)
                mapping_detail = comp_map.get(func_code_str, {})
                op_name = mapping_detail.get("name", f"Operation (FC: {func_code})")
                
                if is_write:
                    if parsed["source_ip"] in auth_ips:
                        alert = {
                            "type": "authorized_write_activity",
                            "details": f"Authorized DNP3 control action ({op_name}) executed on outstation from workstation {parsed['source_ip']}."
                        }
                    else:
                        alert = {
                            "type": "unauthorized_write_attempt",
                            "details": f"CRITICAL: Unauthorized DNP3 control action ({op_name}) attempted on outstation from non-workstation IP {parsed['source_ip']}."
                        }
                        warnings_found += 1
                elif not is_read and not is_write:
                    alert = {
                        "type": "unknown_function_code",
                        "details": f"WARNING: Unknown DNP3 function code {func_code} detected from source IP {parsed['source_ip']}."
                    }
                    warnings_found += 1
                    
        # 3. Siemens S7comm Protocol Validation and Auditing
        elif protocol == "S7Comm":
            parsed = parse_s7_log(entry)
            proto_rules = rules.get("S7Comm", {})
            func_code = parsed.get("function_code", 0)
            
            try:
                func_code = int(func_code)
            except (ValueError, TypeError):
                func_code = -1
                
            comp_map = proto_rules.get("compliance_mapping", {})
            
            allowed_reads = proto_rules.get("allowed_read_function_codes", [])
            monitored_writes = proto_rules.get("monitored_write_function_codes", [])
            
            is_write = func_code in monitored_writes
            is_read = func_code in allowed_reads
            
            func_code_str = str(func_code)
            mapping_detail = comp_map.get(func_code_str, {})
            op_name = mapping_detail.get("name", f"Operation (FC: {func_code})")
            
            if is_write:
                if parsed["source_ip"] in auth_ips:
                    alert = {
                        "type": "authorized_write_activity",
                        "details": f"Authorized S7Comm control action ({op_name}) executed on Siemens PLC from workstation {parsed['source_ip']}."
                    }
                else:
                    alert = {
                        "type": "unauthorized_write_attempt",
                        "details": f"CRITICAL: Unauthorized S7Comm control action ({op_name}) attempted on Siemens PLC from non-workstation IP {parsed['source_ip']}."
                    }
                    warnings_found += 1
            elif not is_read and not is_write:
                alert = {
                    "type": "unknown_function_code",
                    "details": f"WARNING: Unknown S7Comm function code {func_code} detected from source IP {parsed['source_ip']}."
                }
                warnings_found += 1
                
        # 4. IEC 60870-5-104 (IEC 104) Protocol Validation and Auditing
        elif protocol == "IEC104":
            parsed = parse_iec104_log(entry)
            proto_rules = rules.get("IEC104", {})
            type_id = parsed.get("type_id", 0)
            
            try:
                type_id = int(type_id)
            except (ValueError, TypeError):
                type_id = -1
                
            payload = parsed.get("payload", "")
            comp_map = proto_rules.get("compliance_mapping", {})
            
            # Anomaly A: APDU Start Byte Validation (Must begin with 0x68)
            if payload and not payload.lower().startswith("68"):
                alert = {
                    "type": "iec104_start_byte_anomaly",
                    "details": "CRITICAL: Malformed IEC 104 packet missing APCI start byte sync pattern (0x68)."
                }
                comp_map["iec104_start_byte_anomaly"] = {
                    "severity": "CRITICAL",
                    "cii_control": "Sec 6.1 - Protocol Validation",
                    "description": "IEC 104 packet lacks standard start bytes (0x68), indicating malformed transport frames or fuzzed packets."
                }
                warnings_found += 1
            else:
                allowed_reads = proto_rules.get("allowed_read_type_ids", [])
                monitored_writes = proto_rules.get("monitored_write_type_ids", [])
                
                is_write = type_id in monitored_writes
                is_read = type_id in allowed_reads
                
                type_id_str = str(type_id)
                mapping_detail = comp_map.get(type_id_str, {})
                op_name = mapping_detail.get("name", f"ASDU Type ID (Type: {type_id})")
                
                if is_write:
                    if parsed["source_ip"] in auth_ips:
                        alert = {
                            "type": "authorized_write_activity",
                            "details": f"Authorized IEC 104 command action ({op_name}) executed on RTU from workstation {parsed['source_ip']}."
                        }
                    else:
                        alert = {
                            "type": "unauthorized_write_attempt",
                            "details": f"CRITICAL: Unauthorized IEC 104 command action ({op_name}) attempted on RTU from non-workstation IP {parsed['source_ip']}."
                        }
                        warnings_found += 1
                elif not is_read and not is_write:
                    alert = {
                        "type": "unknown_function_code",
                        "details": f"WARNING: Unknown/Unmonitored IEC 104 ASDU Type ID {type_id} detected from source IP {parsed['source_ip']}."
                    }
                    warnings_found += 1
                    
        else:
            alert = {
                "type": "unsupported_protocol",
                "details": f"WARNING: Unsupported protocol '{protocol}' detected in network flow log from IP {entry.get('source_ip')}."
            }
            comp_map = {
                "unsupported_protocol": {
                    "severity": "WARNING",
                    "cii_control": "Sec 6.1 - Protocol Validation",
                    "description": "Network telemetry log belongs to an unrecognized or unmonitored protocol."
                }
            }
            warnings_found += 1
            parsed = {
                "protocol": protocol,
                "timestamp": entry.get("timestamp", datetime.now().isoformat()),
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "payload": payload,
                "notes": entry.get("notes", "Unsupported protocol header.")
            }
            
        if alert:
            # Determine mapping based on event type
            func_code_str = str(parsed.get("function_code") if "function_code" in parsed else parsed.get("type_id"))
            mapping = comp_map.get(alert["type"], comp_map.get(func_code_str, {}))
            severity = mapping.get("severity", "UNKNOWN")
            cii_ctrl = mapping.get("cii_control", "N/A")
            desc = mapping.get("description", "")
            
            # Accumulate operational risk score dynamically based on rules weight mappings
            alert_type = alert["type"]
            weight = risk_weights.get(alert_type, 0)
            accumulated_threat_score += weight
            
            # Check logging severity filter levels
            severity_weight = SEVERITY_LEVELS.get(severity, 1)
            
            if severity_weight >= threshold_weight:
                audit_log_entry = (
                    f"[{parsed.get('timestamp')}] SEVERITY: {severity} | CII Control: {cii_ctrl} | Protocol: {parsed['protocol']}\n"
                    f"  Event Type  : {alert['type']}\n"
                    f"  Details     : {alert['details']}\n"
                    f"  Source IP   : {parsed['source_ip']} -> Destination IP: {parsed['destination_ip']}\n"
                    f"  Payload     : {parsed.get('payload', '')}\n"
                    f"  Log Note    : {parsed.get('notes', '')}\n"
                    f"  Resolution  : {desc}\n"
                    f"{'-' * 80}\n"
                )
                audit_entries.append((severity, audit_log_entry))
                
                # Print feedback to CLI with severity color coding
                color_prefix = ""
                if severity == "CRITICAL":
                    color_prefix = "\033[91m[!] CRITICAL\033[0m"
                elif severity == "WARNING":
                    color_prefix = "\033[93m[!] WARNING\033[0m"
                else:
                    color_prefix = "\033[94m[*] INFO\033[0m"
                    
                print(f"{color_prefix} Protocol: {parsed['protocol']} | IP: {parsed['source_ip']} | CII: {cii_ctrl}")

    # Finalize Threat Level Assessments
    clamped_threat_score = min(100, max(0, accumulated_threat_score))
    threat_status, threat_desc = calculate_threat_level(clamped_threat_score)
    
    # Format the dynamic threat assessment summary
    risk_summary_cli = (
        f"\n[*] =================== OPERATIONAL THREAT ASSESSMENT ===================\n"
        f"[*] Overall Threat Score: {clamped_threat_score}/100\n"
        f"[*] Operational Status  : {threat_status} - {threat_desc}\n"
        f"[*] ====================================================================="
    )
    print(risk_summary_cli)

    # Write findings and threat assessments to persistent report file safely
    try:
        with open(audit_report_path, 'a') as report:
            if audit_entries:
                for severity, entry_text in audit_entries:
                    report.write(entry_text)
            else:
                report.write("No compliance anomalies matching the configured threshold filter were detected.\n")
                
            report.write("\n" + "=" * 80 + "\n")
            report.write(f"SUMMARY STATISTICS:\n")
            report.write(f"Total Logs Parsed     : {total_logs}\n")
            report.write(f"Compliance Alerts     : {len(audit_entries)}\n")
            report.write(f"Filtered Warnings     : {warnings_found}\n")
            report.write(f"Threat Risk Score     : {clamped_threat_score}/100\n")
            report.write(f"System Threat Status  : {threat_status} ({threat_desc})\n")
            report.write("=" * 80 + "\n")
    except Exception:
        print("[-] Critical: Failed to update audit report. Log write error.", file=sys.stderr)
        sys.exit(1)
        
    print("=" * 85)
    print(f"[+] Compliance scan complete. Warnings flagged: {warnings_found}")
    print(f"[+] Comprehensive report written to: {audit_report_path}")
    print("=" * 85)

if __name__ == "__main__":
    main()
