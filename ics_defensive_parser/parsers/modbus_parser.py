def parse_modbus_log(log_entry):
    """
    Extracts telemetry metadata from a passive Modbus TCP log entry.
    """
    return {
        "protocol": "ModbusTCP",
        "timestamp": log_entry.get("timestamp"),
        "source_ip": log_entry.get("source_ip", "0.0.0.0"),
        "destination_ip": log_entry.get("destination_ip", "0.0.0.0"),
        "unit_id": log_entry.get("unit_id", 0),
        "function_code": log_entry.get("function_code", 0),
        "payload": log_entry.get("payload", ""),
        "notes": log_entry.get("notes", "")
    }
