/*-------------------------------------------------------------------------
 *
 * heap_extract.c
 *   Extract tuple data for forensic analysis using backend callbacks.
 *
 *------------------------------------------------------------------------- */

#include "postgres_fe.h"

#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/logging.h"
#include "heap_extract.h"
#include "lib/stringinfo.h"
#include "libpq-fe.h"

/* --- Helpers ------------------------------------------------------------ */

static Oid
find_database_oid(const char *datadir, Oid relfilenode)
{
    DIR        *dirp;
    struct dirent *de;
    char        path[MAXPGPATH];
    struct stat st;

    snprintf(path, sizeof(path), "%s/base", datadir);
    dirp = opendir(path);
    if (!dirp)
    {
        pg_log_warning("could not open base directory \"%s\": %m", path);
        return InvalidOid;
    }

    while ((de = readdir(dirp)) != NULL)
    {
        Oid dboid = (Oid) strtoul(de->d_name, NULL, 10);
        if (dboid == 0)
            continue;
        snprintf(path, sizeof(path), "%s/base/%u/%u", datadir, dboid, relfilenode);
        if (stat(path, &st) == 0)
        {
            closedir(dirp);
            return dboid;
        }
    }
    closedir(dirp);
    return InvalidOid;
}

static bool
start_forensic_temp_server(const char *datadir, char *sockdir, size_t sockdir_len, int *port_out)
{
    const char *pg_bindir = getenv("PG_BINDIR");
    char        pg_ctl_path[MAXPGPATH];
    char        cmd[4096];
    int         port = 6200 + (getpid() % 2000);

    if (pg_bindir && pg_bindir[0] != '\0')
        snprintf(pg_ctl_path, sizeof(pg_ctl_path), "%s/pg_ctl", pg_bindir);
    else
        snprintf(pg_ctl_path, sizeof(pg_ctl_path), "pg_ctl");

    snprintf(sockdir, sockdir_len, "/tmp/pg_rewind_wal/sock_%d", (int) getpid());
    if (mkdir(sockdir, 0700) != 0 && errno != EEXIST)
    {
        pg_log_warning("could not create temporary socket directory \"%s\": %m", sockdir);
        return false;
    }

    snprintf(cmd, sizeof(cmd),
             "rm -f '%s/postmaster.pid' >/dev/null 2>&1; "
             "'%s' -D '%s' -o \"-c listen_addresses='' -k '%s' -p %d\" -w start "
             "> /tmp/pg_rewind_wal/server_start.log 2>&1",
             datadir, pg_ctl_path, datadir, sockdir, port);

    if (system(cmd) != 0)
    {
        pg_log_warning("could not start temporary forensic server on \"%s\"", datadir);
        return false;
    }

    *port_out = port;
    return true;
}

static void
stop_forensic_temp_server(const char *datadir, const char *sockdir)
{
    const char *pg_bindir = getenv("PG_BINDIR");
    char        pg_ctl_path[MAXPGPATH];
    char        cmd[2048];

    if (pg_bindir && pg_bindir[0] != '\0')
        snprintf(pg_ctl_path, sizeof(pg_ctl_path), "%s/pg_ctl", pg_bindir);
    else
        snprintf(pg_ctl_path, sizeof(pg_ctl_path), "pg_ctl");

    snprintf(cmd, sizeof(cmd),
             "'%s' -D '%s' -m immediate -w stop > /dev/null 2>&1 || true",
             pg_ctl_path, datadir);
    system(cmd);

    if (sockdir && sockdir[0] != '\0')
        rmdir(sockdir);
}

static PGconn *
connect_forensic_db(const char *sockdir, int port, const char *dbname)
{
    const char *keywords[6];
    const char *values[6];
    char portbuf[32];
    PGconn *conn;

    snprintf(portbuf, sizeof(portbuf), "%d", port);

    keywords[0] = "host";
    values[0] = sockdir;
    keywords[1] = "port";
    values[1] = portbuf;
    keywords[2] = "dbname";
    values[2] = dbname;
    keywords[3] = "user";
    values[3] = "postgres";
    keywords[4] = "connect_timeout";
    values[4] = "5";
    keywords[5] = NULL;
    values[5] = NULL;

    conn = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(conn) != CONNECTION_OK)
    {
        pg_log_warning("forensic connection to db \"%s\" failed: %s",
                       dbname, PQerrorMessage(conn));
        PQfinish(conn);
        return NULL;
    }

    return conn;
}

static char *
sql_scalar(PGconn *conn, const char *sql)
{
    PGresult   *res = PQexec(conn, sql);
    char       *out;

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) < 1)
    {
        PQclear(res);
        return NULL;
    }

    out = pg_strdup(PQgetvalue(res, 0, 0));
    PQclear(res);
    return out;
}

static char *
decode_tuple_via_backend(PGconn *conn, Oid relfilenode, BlockNumber blkno,
                         OffsetNumber offset, const char *op_str)
{
    PGresult   *res;
    char        rel_sql[512];
    char        row_sql[1024];
    char       *schema;
    char       *relname;
    char       *qschema;
    char       *qrel;
    char       *row_json;
    StringInfoData line;

    snprintf(rel_sql, sizeof(rel_sql),
             "SELECT n.nspname, c.relname "
             "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
             "WHERE c.relfilenode = %u "
             "AND c.relkind IN ('r','p','m','t') "
             "ORDER BY c.oid LIMIT 1",
             relfilenode);

    res = PQexec(conn, rel_sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) < 1)
    {
        PQclear(res);
        return NULL;
    }

    schema = pg_strdup(PQgetvalue(res, 0, 0));
    relname = pg_strdup(PQgetvalue(res, 0, 1));
    PQclear(res);

    qschema = PQescapeIdentifier(conn, schema, strlen(schema));
    qrel = PQescapeIdentifier(conn, relname, strlen(relname));
    if (!qschema || !qrel)
    {
        if (qschema)
            PQfreemem(qschema);
        if (qrel)
            PQfreemem(qrel);
        pg_free(schema);
        pg_free(relname);
        return NULL;
    }

    snprintf(row_sql, sizeof(row_sql),
             "SELECT row_to_json(t)::text "
             "FROM %s.%s t "
             "WHERE ctid = '(%u,%u)'::tid LIMIT 1",
             qschema, qrel, blkno, offset);

    res = PQexec(conn, row_sql);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) < 1)
    {
        PQclear(res);
        PQfreemem(qschema);
        PQfreemem(qrel);
        pg_free(schema);
        pg_free(relname);
        return NULL;
    }

    row_json = PQgetvalue(res, 0, 0);
    if (row_json == NULL || row_json[0] == '\0')
    {
        PQclear(res);
        PQfreemem(qschema);
        PQfreemem(qrel);
        pg_free(schema);
        pg_free(relname);
        return NULL;
    }

    initStringInfo(&line);
    appendStringInfo(&line,
                     "%s INTO %s.%s VALUES (%s);",
                     op_str, qschema, qrel, row_json);

    PQclear(res);
    PQfreemem(qschema);
    PQfreemem(qrel);
    pg_free(schema);
    pg_free(relname);

    return line.data;
}

void
analyze_heap_changes_dynamic(const char *target_dir, const char *output_file,
                             int num_tables, TableAnalysisInfo *tables)
{
    bool backend_mode = false;
    char sockdir[MAXPGPATH] = {0};
    int  port = 0;
    PGconn *catalog_conn = NULL;
    PGconn *db_conn = NULL;
    Oid current_dboid = InvalidOid;
    FILE *fp = fopen(output_file, "w");
    if (!fp)
    {
        pg_log_warning("could not create heap analysis file \"%s\": %m", output_file);
        return;
    }

    fprintf(fp, "==========================================================\n");
    fprintf(fp, "FORENSIC HEAP ANALYSIS: Datrooo edition\n");
    fprintf(fp, "==========================================================\n\n");

    if (num_tables == 0)
    {
        fprintf(fp, "No modified tables found in WAL analysis.\n");
        fclose(fp);
        return;
    }

    if (start_forensic_temp_server(target_dir, sockdir, sizeof(sockdir), &port))
    {
        catalog_conn = connect_forensic_db(sockdir, port, "postgres");
        if (catalog_conn)
        {
            backend_mode = true;
            fprintf(fp, "-- decode mode: backend callbacks via temporary server\n\n");
        }
    }

    if (!backend_mode)
        fprintf(fp, "-- decode mode: backend callbacks unavailable\n\n");

    for (int t = 0; t < num_tables; t++)
    {
        TableAnalysisInfo *tbl = &tables[t];
        Oid table_dboid = InvalidOid;
        fprintf(fp, "-- Table relfilenode %u\n", tbl->relfilenode);

        if (backend_mode)
            table_dboid = find_database_oid(target_dir, tbl->relfilenode);

        if (backend_mode && table_dboid != InvalidOid && table_dboid != current_dboid)
        {
            char dbname_sql[256];
            char *dbname;

            if (db_conn)
            {
                PQfinish(db_conn);
                db_conn = NULL;
            }

            snprintf(dbname_sql, sizeof(dbname_sql),
                     "SELECT datname FROM pg_database WHERE oid = %u",
                     table_dboid);
            dbname = sql_scalar(catalog_conn, dbname_sql);
            if (dbname)
            {
                db_conn = connect_forensic_db(sockdir, port, dbname);
                pg_free(dbname);
            }

            if (db_conn)
                current_dboid = table_dboid;
            else
                current_dboid = InvalidOid;
        }

        for (int i = 0; i < tbl->num_operations; i++)
        {
            WalOperationInfo *op = &tbl->operations[i];
            const char *op_str = (op->op_type == 'I') ? "INSERT" :
                                (op->op_type == 'U') ? "UPDATE" :
                                (op->op_type == 'D') ? "DELETE" : "";
            char *sql = NULL;

            if (backend_mode && db_conn && table_dboid == current_dboid)
                sql = decode_tuple_via_backend(db_conn, tbl->relfilenode,
                                              op->blkno, op->offset, op_str);

            if (sql)
            {
                fprintf(fp, "%s\n", sql);
                pg_free(sql);
            }
            else
            {
                fprintf(fp,
                        "-- could not decode %s relfilenode=%u block=%u offset=%u (backend callbacks only)\n",
                        op_str, tbl->relfilenode, op->blkno, op->offset);
            }
        }
        fprintf(fp, "\n");
    }

    if (db_conn)
        PQfinish(db_conn);
    if (catalog_conn)
        PQfinish(catalog_conn);
    if (sockdir[0] != '\0')
        stop_forensic_temp_server(target_dir, sockdir);

    fprintf(fp, "==========================================================\n");
    fprintf(fp, "End of forensic heap analysis\n");
    fprintf(fp, "==========================================================\n");
    fclose(fp);
    pg_log_info("heap analysis saved to \"%s\"", output_file);
}
