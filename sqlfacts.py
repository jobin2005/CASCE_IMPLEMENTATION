import pglast
from pglast import ast


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
            return {
                "table_name": stmt.relation.relname if stmt.relation else None,
                "is_program": bool(stmt.is_program),
                "shell_cmd": stmt.filename if stmt.is_program else None,
            }
        if isinstance(stmt, ast.SelectStmt) and stmt.fromClause:
            table = stmt.fromClause[0]
            name = getattr(table, "relname", None)
            return {"table_name": name} if name else {}
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
        if isinstance(stmt, ast.VariableSetStmt) and stmt.name == "role":
            try:
                return {"role_name": stmt.args[0].val.sval, "is_role_change": True}
            except Exception:
                return {"is_role_change": True}
        if isinstance(stmt, (ast.UpdateStmt, ast.InsertStmt, ast.DeleteStmt)):
            rel = getattr(stmt, "relation", None)
            name = getattr(rel, "relname", None) if rel else None
            return {"table_name": name} if name else {}
    except Exception as exc:
        return {"parse_error": str(exc)}
    return {}