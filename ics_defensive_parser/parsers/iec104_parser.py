def parse_iec104_log(log_entry):
    """
    Extracts telemetry metadata from a passive IEC 60870-5-104 (IEC 104) log entry.
    IEC 104 uses APDU structures with Type IDs to specify telemetry or command states.
    """
    return {
        "protocol": "IEC104",
        "timestamp": log_entry.get("timestamp"),
        "source_ip": log_entry.get("source_ip", "UNKNOWN"),
        "destination_ip": log_entry.get("destination_ip", "UNKNOWN"),
        "type_id": log_entry.get("type_id", 0),       # ASDU Type Identifier (e.g. 45 = Single Command, 46 = Double Command)
        "payload": log_entry.get("payload", ""),
        "notes": log_entry.get("notes", "")
    }
