#include "postgres_fe.h"

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "access/xlog_internal.h"
#include "common/logging.h"
#include "forensic_decode.h"
#include "heap_extract.h"
#include "wal_analyzer.h"
#include "pg_rewind.h"

#define FORENSIC_OUTPUT_DIR "/tmp/pg_rewind_wal"

static void
ensure_forensic_output_dir(void)
{
	struct stat st;

	if (stat(FORENSIC_OUTPUT_DIR, &st) != 0)
	{
		if (mkdir(FORENSIC_OUTPUT_DIR, 0700) != 0)
		{
			pg_log_warning("could not create forensic output directory \"%s\": %m",
						   FORENSIC_OUTPUT_DIR);
			return;
		}
		pg_log_info("created forensic output directory: %s", FORENSIC_OUTPUT_DIR);
	}
}

void
perform_forensic_decode(const char *target_datadir,
						XLogRecPtr start_lsn, XLogRecPtr end_lsn,
						TimeLineID target_tli)
{
	char		wal_dir[MAXPGPATH];
	char		saved_wal_dir[MAXPGPATH];
	char		saved_data_dir[MAXPGPATH];
	char		command[4096];
	char		heap_output[MAXPGPATH];
	int			num_tables;
	int			i;
	TableAnalysisInfo *tables = NULL;

	pg_log_info("performing forensic WAL analysis");
	pg_log_info("  divergence LSN: %X/%X", LSN_FORMAT_ARGS(start_lsn));
	pg_log_info("  target end LSN: %X/%X", LSN_FORMAT_ARGS(end_lsn));

	ensure_forensic_output_dir();

	snprintf(wal_dir, sizeof(wal_dir), "%s/pg_wal", target_datadir);
	snprintf(saved_wal_dir, sizeof(saved_wal_dir), "%s/saved_wal", FORENSIC_OUTPUT_DIR);

	if (mkdir(saved_wal_dir, 0700) != 0 && errno != EEXIST)
	{
		pg_log_warning("could not create saved WAL directory \"%s\": %m", saved_wal_dir);
		return;
	}
	
	snprintf(saved_data_dir, sizeof(saved_data_dir), "%s/saved_data", FORENSIC_OUTPUT_DIR);
	
	if (mkdir(saved_data_dir, 0700) != 0 && errno != EEXIST)
	{
		pg_log_warning("could not create saved data directory \"%s\": %m", saved_data_dir);
		return;
	}
	
	pg_log_info("copying target datadir for forensic analysis...");
	snprintf(command, sizeof(command),
			 "cp -pr %s/* %s/ 2>/dev/null || true",
			 target_datadir, saved_data_dir);
	system(command);

	pg_log_info("copying WAL files for forensic analysis...");
	snprintf(command, sizeof(command),
			 "cp -p %s/0000000* %s/ 2>/dev/null || true",
			 wal_dir, saved_wal_dir);
	system(command);


	pg_log_info("extracting tuple data from heap pages...");
	
	snprintf(heap_output, sizeof(heap_output), "%s/heap_analysis.sql",
			 FORENSIC_OUTPUT_DIR);
	/* First, analyze WAL to find modified tables */
	analyze_wal_for_tables(saved_data_dir, start_lsn, end_lsn, target_tli);
	
	/* Get results and convert to format needed by heap extraction */
	num_tables = get_modified_tables_count();
	if (num_tables > 0)
	{
		tables = malloc(num_tables * sizeof(TableAnalysisInfo));
		
		for (i = 0; i < num_tables; i++)
		{
			Oid relfilenode;
			int num_ops;
			WalOperation *ops;
			int j;
			
			get_modified_table_info(i, &relfilenode, &num_ops, &ops);
			
			tables[i].relfilenode = relfilenode;
			tables[i].num_operations = num_ops;
			tables[i].operations = malloc(num_ops * sizeof(WalOperationInfo));
			
			/* Convert WalOperation to WalOperationInfo */
			for (j = 0; j < num_ops; j++)
			{
				tables[i].operations[j].blkno = ops[j].blkno;
				tables[i].operations[j].offset = ops[j].offset;
				tables[i].operations[j].op_type = ops[j].op_type;
				tables[i].operations[j].xid = ops[j].xid;
			}
		}
		
	}
	else
	{
		pg_log_info("no modified tables detected in WAL range %X/%X..%X/%X",
					LSN_FORMAT_ARGS(start_lsn),
					LSN_FORMAT_ARGS(end_lsn));
	}

	analyze_heap_changes_dynamic(saved_data_dir, heap_output, num_tables, tables);

	/* Cleanup */
	if (tables)
	{
		for (i = 0; i < num_tables; i++)
			free(tables[i].operations);
		free(tables);
	}
	
	free_wal_analysis();

	pg_log_info("forensic analysis complete - check %s for details",
				FORENSIC_OUTPUT_DIR);
}
