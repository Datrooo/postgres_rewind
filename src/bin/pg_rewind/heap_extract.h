/*-------------------------------------------------------------------------
 *
 * heap_extract.h
 *	  Extract tuple data for forensic analysis via backend callbacks.
 *
 *-------------------------------------------------------------------------
 */
#ifndef HEAP_EXTRACT_H
#define HEAP_EXTRACT_H

#include "postgres_fe.h"
#include "access/xlogdefs.h"

/* Frontend type aliases (not available from backend headers) */
#ifndef FRONTEND_HEAP_TYPES
#define FRONTEND_HEAP_TYPES
typedef uint32 BlockNumber;
typedef uint16 OffsetNumber;
#endif

/* Structure for WAL operation info passed from analyzer */
typedef struct WalOperationInfo
{
	BlockNumber blkno;
	OffsetNumber offset;
	char		op_type;		/* 'I' = INSERT, 'U' = UPDATE, 'D' = DELETE */
	uint32		xid;
} WalOperationInfo;

/* Structure for table analysis info */
typedef struct TableAnalysisInfo
{
	Oid			relfilenode;
	int			num_operations;
	WalOperationInfo *operations;
} TableAnalysisInfo;

/* Analyze all heap changes - dynamic version using WAL analysis */
extern void analyze_heap_changes_dynamic(const char *target_dir, const char *output_file,
										 int num_tables, TableAnalysisInfo *tables);

#endif							/* HEAP_EXTRACT_H */
