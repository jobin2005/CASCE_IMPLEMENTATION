#include "postgres.h"
#include "fmgr.h"
#include "executor/executor.h"
#include "tcop/utility.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "commands/dbcommands.h"
#include "libpq/libpq-be.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

PG_MODULE_MAGIC;

/* Presence of this file is the on/off switch for logging.
 * Created by logger.sh on "start", removed on "stop", so that
 * this extension can be started/stopped without restarting Postgres. */
#define CASCE_LOGGING_FLAG "/dataset_workspace/.casce_logging_active"

void _PG_init(void);
void _PG_fini(void);

static ExecutorStart_hook_type prev_ExecutorStart = NULL;

static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

static long cached_session_start_time = 0;

static void log_casce_event(const char* event_type, const char* query) {
    FILE *fp;
    char safe_query[2048] = {0};
    int i;
    const char* dbname = "unknown";
    const char* username = "unknown";
    const char* client_addr = "local";
    const char* client_port = "0";

    if (!query) return;

    // Logging is toggled on/off by logger.sh via this flag file's presence.
    if (access(CASCE_LOGGING_FLAG, F_OK) != 0) return;

    // Open file to append structured event log for collector
    fp = fopen("/dataset_workspace/postgres_events.json", "a");
    if (!fp) return;
    
    // Very basic JSON escaping (replacing quotes/newlines)
    snprintf(safe_query, sizeof(safe_query)-1, "%s", query);
    for(i=0; safe_query[i]; i++) {
        if(safe_query[i] == '"' || safe_query[i] == '\n' || safe_query[i] == '\r' || safe_query[i] == '\\') 
            safe_query[i] = ' ';
    }

    dbname = get_database_name(MyDatabaseId);
    if (!dbname) dbname = "unknown";
    
    username = GetUserNameFromId(GetUserId(), true);
    if (!username) username = "unknown";
    
    const char *spoofed_users[] = {"db_admin", "analyst_bob", "service_alice", "dev_charlie", "postgres"};
    if (strcmp(username, "postgres") == 0) {
        username = spoofed_users[MyProcPid % 5];
    }
    
    if (MyProcPort && MyProcPort->remote_host) client_addr = MyProcPort->remote_host;
    if (MyProcPort && MyProcPort->remote_port) client_port = MyProcPort->remote_port;

    char spoofed_ip[32];
    char spoofed_port[16];
    if (strcmp(client_addr, "[local]") == 0) {
        snprintf(spoofed_ip, sizeof(spoofed_ip), "192.168.1.%d", (MyProcPid % 254) + 1);
        snprintf(spoofed_port, sizeof(spoofed_port), "%d", 40000 + (MyProcPid % 25000));
        client_addr = spoofed_ip;
        client_port = spoofed_port;
    }

    if (cached_session_start_time == 0) {
        cached_session_start_time = (long)time(NULL);
    }

    fprintf(fp, "{\"session_id\": %d, \"session_start_time\": %ld, \"backend_pid\": %d, \"timestamp\": %ld, \"event_type\": \"%s\", \"query\": \"%s\", \"database\": \"%s\", \"username\": \"%s\", \"client_addr\": \"%s\", \"client_port\": \"%s\"}\n",
        MyProcPid, cached_session_start_time, MyProcPid, (long)time(NULL), event_type, safe_query, dbname, username, client_addr, client_port);
    fclose(fp);
}

static void casce_ExecutorStart(QueryDesc *queryDesc, int eflags) {
    if (queryDesc && queryDesc->sourceText) {
        log_casce_event("ExecutorStart", queryDesc->sourceText);
    }
    if (prev_ExecutorStart) prev_ExecutorStart(queryDesc, eflags);
    else standard_ExecutorStart(queryDesc, eflags);
}

static void casce_ExecutorEnd(QueryDesc *queryDesc) {
    log_casce_event("ExecutorEnd", queryDesc->sourceText);
    if (prev_ExecutorEnd) prev_ExecutorEnd(queryDesc);
    else standard_ExecutorEnd(queryDesc);
}

static void casce_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
#if PG_VERSION_NUM >= 140000
    bool readOnlyTree,
#endif
    ProcessUtilityContext context, ParamListInfo params, QueryEnvironment *queryEnv, DestReceiver *dest, QueryCompletion *qc) {
    
    log_casce_event("ProcessUtility", queryString);
    
    if (prev_ProcessUtility) {
#if PG_VERSION_NUM >= 140000
        prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
#else
        prev_ProcessUtility(pstmt, queryString, context, params, queryEnv, dest, qc);
#endif
    } else {
#if PG_VERSION_NUM >= 140000
        standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
#else
        standard_ProcessUtility(pstmt, queryString, context, params, queryEnv, dest, qc);
#endif
    }
}

void _PG_init(void) {
    prev_ExecutorStart = ExecutorStart_hook;
    ExecutorStart_hook = casce_ExecutorStart;
    
    prev_ExecutorEnd = ExecutorEnd_hook;
    ExecutorEnd_hook = casce_ExecutorEnd;
    
    prev_ProcessUtility = ProcessUtility_hook;
    ProcessUtility_hook = casce_ProcessUtility;
}

void _PG_fini(void) {
    ExecutorStart_hook = prev_ExecutorStart;
    ExecutorEnd_hook = prev_ExecutorEnd;
    ProcessUtility_hook = prev_ProcessUtility;
}
