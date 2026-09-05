NODE_TYPES = {"Session", "Role", "Query", "Table", "Process", "File", "Endpoint"}
EDGE_TYPES = {"executes", "accesses", "backed_by", "spawns", "opens", "connects_to"}

NODE_KEY = {
    "Session":  lambda a: a["session_key"],
    "Query":    lambda a: a["event_id"],
    "Table":    lambda a: a["table_name"],
    "Process":  lambda a: a["pid"],   # proc_start_time not yet in kernel schema; pid alone
                                       # is acceptable within one bounded dataset-generation run
    "Endpoint": lambda a: (a["dest_ip"], a["dest_port"]),
    "File":     lambda a: a["filepath"],
    "Role":     lambda a: a["role_name"],
}