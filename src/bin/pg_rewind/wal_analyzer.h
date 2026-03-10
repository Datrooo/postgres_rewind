/*-------------------------------------------------------------------------
 *
 * wal_analyzer.h
 *	  WAL analysis for dynamic table discovery
 *
 *-------------------------------------------------------------------------
 */
#ifndef WAL_ANALYZER_H
#define WAL_ANALYZER_H

#include "access/xlogdefs.h"
#include "storage/block.h"

/* Operation type stored in WAL */
typedef unsigned int Oid;
typedef unsigned short OffsetNumber;

/* Structure to track individual WAL operation */
typedef struct WalOperation
{
	BlockNumber blkno;
	OffsetNumber offset;
	char		op_type;		/* 'I' = INSERT, 'U' = UPDATE, 'D' = DELETE */
	uint32		xid;			/* transaction ID */
} WalOperation;

/* Forensic output directory */
#define FORENSIC_OUTPUT_DIR "/tmp/pg_rewind_wal"

/* Function prototypes */
extern void analyze_wal_for_tables(const char *datadir, XLogRecPtr start_lsn, XLogRecPtr end_lsn, TimeLineID tli);
extern int get_modified_tables_count(void);
extern void get_modified_table_info(int index, Oid *relfilenode, int *num_ops, WalOperation **ops);
extern void free_wal_analysis(void);

#endif							/* WAL_ANALYZER_H */
