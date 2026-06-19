def parse_s7_log(log_entry):
    """
    Extracts telemetry metadata from a passive S7comm log entry.
    S7comm operates over ISO-on-TCP (COTP) and processes PLC read, write, start, and stop events.
    """
    return {
        "protocol": "S7Comm",
        "timestamp": log_entry.get("timestamp"),
        "source_ip": log_entry.get("source_ip", "0.0.0.0"),
        "destination_ip": log_entry.get("destination_ip", "0.0.0.0"),
        "message_type": log_entry.get("message_type", 1),       # e.g., 1 = Job request, 3 = Ack_Data
        "function_code": log_entry.get("function_code", 0),      # e.g., 0xf0 = Setup, 0x05 = Write, 0x29 = Stop PLC
        "payload": log_entry.get("payload", ""),
        "notes": log_entry.get("notes", "")
    }
