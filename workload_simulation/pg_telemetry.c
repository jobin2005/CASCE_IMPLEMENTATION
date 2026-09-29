/*
 * pg_telemetry -- CASCE PostgreSQL-plane collector.
 *
 * Emits one JSON line per top-level statement into postgres_events.json,
 * in exactly the record shape datagen/codegen.py produces for the
 * synthetic corpus (see _postgres_record there), so live runs go through
 * Algorithms 1-4 unchanged:
 *
 *   session_id, session_start_time, backend_pid, timestamp, event_type,
 *   query, database, username, client_addr, client_port
 *
 * Parity rules with the synthetic corpus:
 *   - timestamp is unix epoch seconds WITH microseconds (codegen writes
 *     fractional seconds; the old time(NULL) was whole seconds only).
 *   - session_start_time is the backend's real start time (MyStartTime).
 *   - only client backends are logged (not parallel workers, autovacuum, ...).
 *   - only TOP-LEVEL statements are logged: SELECT/INSERT/UPDATE/DELETE ->
 *     ExecutorStart + ExecutorEnd, everything else (COPY, DDL, ...) ->
 *     ProcessUtility.  Queries nested inside a utility statement or a
 *     function (e.g. the SELECT inside COPY (SELECT ...) TO PROGRAM) are
 *     not logged, matching codegen, which emits one record set per SQL step.
 *   - username / client_addr / client_port are the REAL values. The earlier
 *     realtime-evaluation version replaced them with invented users and IPs;
 *     that is removed -- live evaluation must describe what actually ran.
 *
 * Ground truth is kept OUT of the event stream: if a session's
 * application_name is "casce_label=<Label>[:<scenario>]" (set by the workload
 * scripts through PGAPPNAME), the session is recorded once in
 * session_labels.jsonl. The pipeline never reads that file, so the label
 * cannot leak into model features.
 *
 * Logging is toggled by the presence of CASCE_LOGGING_FLAG (logger.sh).
 */
#include "postgres.h"
#include "fmgr.h"
#include "executor/executor.h"
#include "tcop/utility.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "commands/dbcommands.h"
#include "libpq/libpq-be.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

PG_MODULE_MAGIC;

#define CASCE_LOGGING_FLAG "/dataset_workspace/.casce_logging_active"
#define CASCE_PG_LOG       "/dataset_workspace/postgres_events.json"
#define CASCE_LABEL_LOG    "/dataset_workspace/session_labels.jsonl"
#define CASCE_LABEL_PREFIX "casce_label="
#define CASCE_MAX_QUERY    4096

void _PG_init(void);
void _PG_fini(void);

static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ExecutorRun_hook_type prev_ExecutorRun = NULL;
static ExecutorFinish_hook_type prev_ExecutorFinish = NULL;
static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

/* depth of statement execution; 0 == top level (same scheme as pg_stat_statements) */
static int nesting_level = 0;
static bool label_written = false;

/* JSON-escape src into dst (always NUL-terminated, truncates safely). */
static void json_escape(char *dst, size_t dstlen, const char *src)
{
    size_t j = 0;

    for (; src && *src && j + 7 < dstlen; src++)
    {
        unsigned char c = (unsigned char) *src;

        if (c == '"' || c == '\\')
        {
            dst[j++] = '\\';
            dst[j++] = c;
        }
        else if (c == '\n')
        {
            dst[j++] = '\\';
            dst[j++] = 'n';
        }
        else if (c == '\r')
        {
            dst[j++] = '\\';
            dst[j++] = 'r';
        }
        else if (c == '\t')
        {
            dst[j++] = '\\';
            dst[j++] = 't';
        }
        else if (c < 0x20)
            j += snprintf(dst + j, dstlen - j, "\\u%04x", c);
        else
            dst[j++] = c;
    }
    dst[j] = '\0';
}

static void write_session_label(void)
{
    FILE *fp;
    char label[256];

    label_written = true;
    if (!application_name ||
        strncmp(application_name, CASCE_LABEL_PREFIX, strlen(CASCE_LABEL_PREFIX)) != 0)
        return;

    json_escape(label, sizeof(label), application_name + strlen(CASCE_LABEL_PREFIX));
    fp = fopen(CASCE_LABEL_LOG, "a");
    if (!fp)
        return;
    fprintf(fp, "{\"session_id\": %d, \"session_start_time\": %ld, \"label\": \"%s\"}\n",
            MyProcPid, (long) MyStartTime, label);
    fclose(fp);
}

static void log_casce_event(const char *event_type, const char *query)
{
    FILE *fp;
    struct timespec now;
    char safe_query[CASCE_MAX_QUERY * 2];
    char safe_user[256];
    char safe_db[256];
    const char *dbname;
    const char *username;
    const char *client_addr = "[local]";
    const char *client_port = "0";

    /* client sessions only: parallel workers, autovacuum etc. re-run a
     * client's query under their own pid and would appear as extra sessions */
    if (!query || nesting_level != 0 || MyBackendType != B_BACKEND)
        return;
    if (access(CASCE_LOGGING_FLAG, F_OK) != 0)
        return;

    clock_gettime(CLOCK_REALTIME, &now);

    if (!label_written)
        write_session_label();

    fp = fopen(CASCE_PG_LOG, "a");
    if (!fp)
        return;

    dbname = get_database_name(MyDatabaseId);
    username = GetUserNameFromId(GetUserId(), true);
    if (MyProcPort && MyProcPort->remote_host)
        client_addr = MyProcPort->remote_host;
    if (MyProcPort && MyProcPort->remote_port && MyProcPort->remote_port[0])
        client_port = MyProcPort->remote_port;

    json_escape(safe_query, sizeof(safe_query), query);
    json_escape(safe_db, sizeof(safe_db), dbname ? dbname : "unknown");
    json_escape(safe_user, sizeof(safe_user), username ? username : "unknown");

    fprintf(fp,
            "{\"session_id\": %d, \"session_start_time\": %ld, \"backend_pid\": %d, "
            "\"timestamp\": %ld.%06ld, \"event_type\": \"%s\", \"query\": \"%s\", "
            "\"database\": \"%s\", \"username\": \"%s\", \"client_addr\": \"%s\", "
            "\"client_port\": \"%s\"}\n",
            MyProcPid, (long) MyStartTime, MyProcPid,
            (long) now.tv_sec, now.tv_nsec / 1000, event_type, safe_query,
            safe_db, safe_user, client_addr, client_port);
    fclose(fp);
}

static void casce_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
    if (queryDesc && queryDesc->sourceText)
        log_casce_event("ExecutorStart", queryDesc->sourceText);
    if (prev_ExecutorStart)
        prev_ExecutorStart(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
}

static void casce_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction,
                              uint64 count, bool execute_once)
{
    nesting_level++;
    PG_TRY();
    {
        if (prev_ExecutorRun)
            prev_ExecutorRun(queryDesc, direction, count, execute_once);
        else
            standard_ExecutorRun(queryDesc, direction, count, execute_once);
    }
    PG_FINALLY();
    {
        nesting_level--;
    }
    PG_END_TRY();
}

static void casce_ExecutorFinish(QueryDesc *queryDesc)
{
    nesting_level++;
    PG_TRY();
    {
        if (prev_ExecutorFinish)
            prev_ExecutorFinish(queryDesc);
        else
            standard_ExecutorFinish(queryDesc);
    }
    PG_FINALLY();
    {
        nesting_level--;
    }
    PG_END_TRY();
}

static void casce_ExecutorEnd(QueryDesc *queryDesc)
{
    if (queryDesc && queryDesc->sourceText)
        log_casce_event("ExecutorEnd", queryDesc->sourceText);
    if (prev_ExecutorEnd)
        prev_ExecutorEnd(queryDesc);
    else
        standard_ExecutorEnd(queryDesc);
}

static void casce_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
                                 bool readOnlyTree, ProcessUtilityContext context,
                                 ParamListInfo params, QueryEnvironment *queryEnv,
                                 DestReceiver *dest, QueryCompletion *qc)
{
    log_casce_event("ProcessUtility", queryString);

    nesting_level++;
    PG_TRY();
    {
        if (prev_ProcessUtility)
            prev_ProcessUtility(pstmt, queryString, readOnlyTree, context,
                                params, queryEnv, dest, qc);
        else
            standard_ProcessUtility(pstmt, queryString, readOnlyTree, context,
                                    params, queryEnv, dest, qc);
    }
    PG_FINALLY();
    {
        nesting_level--;
    }
    PG_END_TRY();
}

void _PG_init(void)
{
    prev_ExecutorStart = ExecutorStart_hook;
    ExecutorStart_hook = casce_ExecutorStart;
    prev_ExecutorRun = ExecutorRun_hook;
    ExecutorRun_hook = casce_ExecutorRun;
    prev_ExecutorFinish = ExecutorFinish_hook;
    ExecutorFinish_hook = casce_ExecutorFinish;
    prev_ExecutorEnd = ExecutorEnd_hook;
    ExecutorEnd_hook = casce_ExecutorEnd;
    prev_ProcessUtility = ProcessUtility_hook;
    ProcessUtility_hook = casce_ProcessUtility;
}

void _PG_fini(void)
{
    ExecutorStart_hook = prev_ExecutorStart;
    ExecutorRun_hook = prev_ExecutorRun;
    ExecutorFinish_hook = prev_ExecutorFinish;
    ExecutorEnd_hook = prev_ExecutorEnd;
    ProcessUtility_hook = prev_ProcessUtility;
}
