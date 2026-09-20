import pglast
from pglast import ast


def _extract_tables_from_node(node):
    tables = []
    if not node:
        return tables
    if hasattr(node, "relname") and node.relname:
        tables.append(node.relname)
    if hasattr(node, "larg"):
        tables.extend(_extract_tables_from_node(node.larg))
    if hasattr(node, "rarg"):
        tables.extend(_extract_tables_from_node(node.rarg))
    return tables


def _extract_tables_from_from_clause(from_clause):
    tables = []
    if not from_clause:
        return tables
    for item in from_clause:
        tables.extend(_extract_tables_from_node(item))
    return tables


def extract_query_facts(query_text: str) -> dict:
    """Parse one SQL statement into the facts Algorithm 2 needs.
    Never raises -- a parse failure degrades to {"parse_error": ...}
    so one bad query never crashes the pipeline."""
    if not query_text:
        return {}
    try:
        parsed = pglast.parse_sql(query_text)
        if not parsed:
            return {}
        stmt = parsed[0].stmt

        if isinstance(stmt, ast.CopyStmt):
            table_name = stmt.relation.relname if stmt.relation else None
            tables = [table_name] if table_name else []
            if not tables and getattr(stmt, "query", None):
                sub_query = stmt.query
                if isinstance(sub_query, ast.SelectStmt) and sub_query.fromClause:
                    tables = _extract_tables_from_from_clause(sub_query.fromClause)
            return {
                "table_name": tables[0] if tables else None,
                "tables": tables,
                "is_program": bool(stmt.is_program),
                "shell_cmd": stmt.filename if stmt.is_program else None,
            }
        if isinstance(stmt, ast.SelectStmt) and stmt.fromClause:
            tables = _extract_tables_from_from_clause(stmt.fromClause)
            return {"table_name": tables[0] if tables else None, "tables": tables}
        if isinstance(stmt, ast.DropStmt):
            names = [obj[-1].sval for obj in stmt.objects]
            return {"table_name": names[0] if names else None, "is_drop": True}
        if isinstance(stmt, ast.CreateRoleStmt):
            opts = stmt.options or []
            return {
                "role_name": stmt.role,
                "is_role_change": True,
                "is_superuser": any(getattr(o, "defname", "") == "superuser" for o in opts),
            }
        if isinstance(stmt, ast.AlterRoleStmt):
            # e.g. "ALTER ROLE branch_manager WITH SUPERUSER" -- a privilege
            # escalation on an EXISTING role, distinct from CreateRoleStmt.
            # Previously unhandled: fell through to {} (empty dict), leaving
            # the query node disconnected from any Role node -- invisible to
            # every ACCOUNT_MANIPULATION-style behavior template.
            opts = stmt.options or []
            role_name = getattr(stmt.role, "rolename", None) if stmt.role else None
            is_superuser = any(
                getattr(o, "defname", "") == "superuser" and
                getattr(getattr(o, "arg", None), "boolval", True)  # WITH SUPERUSER defaults true; WITH NOSUPERUSER sets boolval False
                for o in opts
            )
            return {
                "role_name": role_name,
                "is_role_change": True,
                "is_privilege_escalation": is_superuser,
                "is_superuser": is_superuser,
            }
        if isinstance(stmt, ast.TruncateStmt):
            # e.g. "TRUNCATE TABLE audit_logs" -- destructive, but structurally
            # distinct from DROP (table survives, rows don't). Previously
            # unhandled: fell through to {}, so DESTRUCTIVE_DB_OPERATION could
            # never match a truncate.
            relations = stmt.relations or ()
            names = [getattr(r, "relname", None) for r in relations]
            names = [n for n in names if n]
            return {
                "table_name": names[0] if names else None,
                "is_destructive": True,
                "is_truncate": True,
            }
        if isinstance(stmt, ast.AlterSystemStmt):
            # e.g. "ALTER SYSTEM SET log_statement = 'none'" -- server-wide
            # configuration tampering (classic log-evasion / defense-impairment
            # move). Previously unhandled: fell through to {}, so
            # DEFENSE_IMPAIRMENT had nothing to match against.
            inner = stmt.setstmt
            setting_name = getattr(inner, "name", None) if inner else None
            new_value = None
            try:
                new_value = inner.args[0].val.sval
            except Exception:
                pass
            return {
                "setting_name": setting_name,
                "setting_value": new_value,
                "is_system_config": True,
            }
        if isinstance(stmt, ast.VariableSetStmt) and stmt.name == "role":
            try:
                return {"role_name": stmt.args[0].val.sval, "is_role_change": True}
            except Exception:
                return {"is_role_change": True}
        if isinstance(stmt, ast.VariableSetStmt) and stmt.name != "role":
            return {
                "setting_name": stmt.name,
                "is_system_config": True,
            }
        if isinstance(stmt, (ast.UpdateStmt, ast.InsertStmt, ast.DeleteStmt)):
            rel = getattr(stmt, "relation", None)
            name = getattr(rel, "relname", None) if rel else None
            return {"table_name": name} if name else {}
    except Exception as exc:
        return {"parse_error": str(exc)}
    return {}