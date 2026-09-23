NODE_TYPES = {"Session", "Role", "Query", "Table", "Process", "File", "Endpoint", "Configuration"}
EDGE_TYPES = {"executes", "accesses", "backed_by", "spawns", "opens", "connects_to", "modifies"}

NODE_KEY = {
    "Session":  lambda a: a["session_key"],
    "Query":    lambda a: a["event_id"],
    "Table":    lambda a: a["table_name"],
    "Process":  lambda a: a["pid"],   # proc_start_time not yet in kernel schema; pid alone
                                       # is acceptable within one bounded dataset-generation run
    "Endpoint": lambda a: (a["dest_ip"], a["dest_port"]),
    "File":     lambda a: a["filepath"],
    "Role":     lambda a: a["role_name"],
    # ALTER SYSTEM SET / SET ... (sqlfacts: is_system_config) -- previously had no
    # node type at all, so config-tampering queries (log_statement disable, etc.)
    # produced a disconnected Query node invisible to DEFENSE_IMPAIRMENT.
    "Configuration": lambda a: a["setting_name"],
}