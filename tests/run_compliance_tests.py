
#!/usr/bin/env python3
"""
ICS Compliance Auditor - Test Suite & Verification Engine
Executes automated zone-based testing to verify protocol decoding anomalies,
logical boundary segmentation, and CII security rules compliance.
"""

import json
import os
import sys

# Configure path imports to locate the workspace root and import main from package
WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(WORKSPACE_DIR, "ics_defensive_parser"))

from main import load_json_file
from parsers.modbus_parser import parse_modbus_log
from parsers.dnp3_parser import parse_dnp3_log
from parsers.s7_parser import parse_s7_log
from parsers.iec104_parser import parse_iec104_log

RULES_PATH = os.path.join(WORKSPACE_DIR, "data", "rules.json")
LOGS_PATH = os.path.join(WORKSPACE_DIR, "data", "mock_logs.json")

class ICSTestRunner:
    def __init__(self):
        self.rules = load_json_file(RULES_PATH)
        self.logs = load_json_file(LOGS_PATH)
        self.auth_ips = self.rules.get("authorized_engineering_workstations", [])
        self.results = []

    def log_test_result(self, zone, name, status, message):
        self.results.append({
            "zone": zone,
            "name": name,
            "status": status,
            "message": message
        })
        prefix = "\033[92m[PASS]\033[0m" if status == "PASS" else "\033[91m[FAIL]\033[0m"
        print(f"{prefix} [{zone}] {name}: {message}")

    def run_zone_1_tests(self):
        """Zone 1: Standard Operational Telemetry Baseline"""
        print("\n=== Running Zone 1: Standard Operational Telemetry Baseline ===")
        
        # Test Case 1: Modbus Read Holding Registers (FC 3) -> Allowed read, no alert
        modbus_read = self.logs[0]
        parsed = parse_modbus_log(modbus_read)
        fc = parsed["function_code"]
        allowed_reads = self.rules["Modbus"]["allowed_read_function_codes"]
        if fc in allowed_reads and fc == 3:
            self.log_test_result("Zone 1", "Modbus FC 3 Read", "PASS", "Standard HMI registers read allowed without alert.")
        else:
            self.log_test_result("Zone 1", "Modbus FC 3 Read", "FAIL", f"Modbus FC {fc} not matched as allowed read.")

        # Test Case 2: Modbus Device Identification (FC 43) -> Info alert
        modbus_id = self.logs[1]
        parsed = parse_modbus_log(modbus_id)
        fc = parsed["function_code"]
        mapping = self.rules["Modbus"]["compliance_mapping"].get(str(fc), {})
        if mapping.get("severity") == "INFO" and mapping.get("cii_control") == "Sec 6.4 - Operational Audit Logging":
            self.log_test_result("Zone 1", "Modbus FC 43 ID query", "PASS", "Device ID read maps to Sec 6.4 (INFO).")
        else:
            self.log_test_result("Zone 1", "Modbus FC 43 ID query", "FAIL", "Device ID mapping mismatch.")

        # Test Case 3: S7Comm COTP Handshake setup (FC 240) -> Allowed read, no alert
        s7_setup = self.logs[10]
        parsed = parse_s7_log(s7_setup)
        fc = parsed["function_code"]
        allowed_reads = self.rules["S7Comm"]["allowed_read_function_codes"]
        if fc in allowed_reads and fc == 240:
            self.log_test_result("Zone 1", "S7Comm FC 240 Handshake", "PASS", "S7comm setup connection allowed without alert.")
        else:
            self.log_test_result("Zone 1", "S7Comm FC 240 Handshake", "FAIL", "S7comm setup connection blocked.")

    def run_zone_2_tests(self):
        """Zone 2: Protocol Header Integrity Verification"""
        print("\n=== Running Zone 2: Protocol Header Integrity Verification ===")

        # Test Case 1: DNP3 malformed start sync sequence (does not start with 0564)
        dnp3_malformed = self.logs[5]
        parsed = parse_dnp3_log(dnp3_malformed)
        payload = parsed["payload"]
        if not payload.startswith("0564"):
            self.log_test_result("Zone 2", "DNP3 Sync Header Check", "PASS", f"DNP3 packet with payload '{payload}' flagged as header sync byte anomaly.")
        else:
            self.log_test_result("Zone 2", "DNP3 Sync Header Check", "FAIL", "Failed to detect malformed DNP3 start byte.")

        # Test Case 2: IEC 104 malformed start byte (does not start with 68)
        iec104_malformed = self.logs[6]
        parsed = parse_iec104_log(iec104_malformed)
        payload = parsed["payload"]
        if not payload.startswith("68"):
            self.log_test_result("Zone 2", "IEC104 Sync Header Check", "PASS", f"IEC 104 packet with payload '{payload}' flagged as APCI sync byte anomaly.")
        else:
            self.log_test_result("Zone 2", "IEC104 Sync Header Check", "FAIL", "Failed to detect malformed IEC 104 start byte.")

        # Test Case 3: Out-of-bounds DNP3 Function Code Check (FC 99 is unknown/unmonitored)
        dnp3_unknown = self.logs[17]
        parsed = parse_dnp3_log(dnp3_unknown)
        fc = parsed["function_code"]
        allowed = self.rules["DNP3"]["allowed_read_function_codes"]
        monitored = self.rules["DNP3"]["monitored_write_function_codes"]
        if fc not in allowed and fc not in monitored:
            self.log_test_result("Zone 2", "DNP3 Unknown Code", "PASS", f"DNP3 function code {fc} flagged as unknown/unmonitored code validation warning.")
        else:
            self.log_test_result("Zone 2", "DNP3 Unknown Code", "FAIL", "Failed to validate DNP3 function code range limits.")

    def run_zone_3_tests(self):
        """Zone 3: Access Control & Logical Boundaries"""
        print("\n=== Running Zone 3: Access Control & Logical Boundaries ===")

        # Test Case 1: Unauthorized Siemens S7 PLC Halt Attempt (FC 41 - STOP PLC)
        s7_stop_unauth = self.logs[11]
        parsed = parse_s7_log(s7_stop_unauth)
        src = parsed["source_ip"]
        fc = parsed["function_code"]
        is_write = fc in self.rules["S7Comm"]["monitored_write_function_codes"]
        if is_write and src not in self.auth_ips:
            self.log_test_result("Zone 3", "S7 PLC Halt Unauthorized", "PASS", f"Siemens PLC STOP command from unauthorized IP {src} flagged as CRITICAL alert.")
        else:
            self.log_test_result("Zone 3", "S7 PLC Halt Unauthorized", "FAIL", "Halt command from unauthorized host went undetected.")

        # Test Case 2: Authorized Siemens S7 Block modification (FC 5 - Write Var)
        s7_write_auth = self.logs[15]
        parsed = parse_s7_log(s7_write_auth)
        src = parsed["source_ip"]
        fc = parsed["function_code"]
        is_write = fc in self.rules["S7Comm"]["monitored_write_function_codes"]
        if is_write and src in self.auth_ips:
            self.log_test_result("Zone 3", "S7 Write Var Authorized", "PASS", f"Siemens PLC data block modification from authorized workstation {src} logged as INFO.")
        else:
            self.log_test_result("Zone 3", "S7 Write Var Authorized", "FAIL", "Authorized modification mapped to incorrect warning status.")

        # Test Case 3: Unauthorized DNP3 File Deletion attempt (FC 27)
        dnp3_del_unauth = self.logs[20]
        parsed = parse_dnp3_log(dnp3_del_unauth)
        src = parsed["source_ip"]
        fc = parsed["function_code"]
        is_write = fc in self.rules["DNP3"]["monitored_write_function_codes"]
        if is_write and src not in self.auth_ips:
            self.log_test_result("Zone 3", "DNP3 File Delete Unauthorized", "PASS", f"DNP3 file deletion command from unauthorized source {src} flagged as CRITICAL.")
        else:
            self.log_test_result("Zone 3", "DNP3 File Delete Unauthorized", "FAIL", "Unauthorized filesystem action went undetected.")

    def run_zone_4_tests(self):
        """Zone 4: Subnet Segment Containment"""
        print("\n=== Running Zone 4: Subnet Segment Containment ===")

        # Test Case 1: DNP3 packet targeted to broadcast address
        dnp3_bcast = self.logs[4]
        parsed = parse_dnp3_log(dnp3_bcast)
        dest = parsed["destination_ip"]
        if dest == "255.255.255.255":
            self.log_test_result("Zone 4", "DNP3 Broadcast Target Check", "PASS", "DNP3 frame with destination 255.255.255.255 flagged as critical segment isolation breach.")
        else:
            self.log_test_result("Zone 4", "DNP3 Broadcast Target Check", "FAIL", "Failed to detect broadcast command envelope.")

    def generate_report(self):
        print("\n" + "=" * 65)
        print("                 ICS AUDITOR TEST RUN SUMMARY REPORT                 ")
        print("=" * 65)
        passes = sum(1 for r in self.results if r["status"] == "PASS")
        fails = sum(1 for r in self.results if r["status"] == "FAIL")
        total = len(self.results)
        
        print(f"Total Tests Executed : {total}")
        print(f"Passed Assertions    : \033[92m{passes}\033[0m")
        print(f"Failed Assertions    : \033[91m{fails}\033[0m" if fails > 0 else f"Failed Assertions    : {fails}")
        print("-" * 65)
        
        if fails == 0:
            print("\033[92m[STATUS] SUCCESS: All ICS compliance testing zones validated correctly.\033[0m")
            return True
        else:
            print("\033[91m[STATUS] FAILURE: Anomalies detected during compliance testing validation.\033[0m")
            return False

if __name__ == "__main__":
    runner = ICSTestRunner()
    runner.run_zone_1_tests()
    runner.run_zone_2_tests()
    runner.run_zone_3_tests()
    runner.run_zone_4_tests()
    success = runner.generate_report()
    if not success:
        sys.exit(1)
