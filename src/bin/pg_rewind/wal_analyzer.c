#include "postgres_fe.h"

#include <dirent.h>
#include <sys/stat.h>

#include "access/xlog_internal.h"
#include "access/xlogreader.h"
#include "common/fe_memutils.h"
#include "common/logging.h"
#include "fe_utils/archive.h"
#include "getopt_long.h"

#include "wal_analyzer.h"

/* From heapam_xlog.h */
#define XLOG_HEAP_INSERT		0x00
#define XLOG_HEAP_DELETE		0x10
#define XLOG_HEAP_UPDATE		0x20
#define XLOG_HEAP_HOT_UPDATE	0x40
#define XLOG_HEAP_OPMASK		0x70

#define XLOG_HEAP2_MULTI_INSERT 0x50

#define RM_HEAP_ID				10
#define RM_HEAP2_ID				11

/* WAL record structures */
typedef struct xl_heap_insert
{
	OffsetNumber offnum;
	uint8		flags;
} xl_heap_insert;

typedef struct xl_heap_delete
{
	TransactionId xmax;
	OffsetNumber offnum;
	uint8		infobits_set;
	uint8		flags;
} xl_heap_delete;

typedef struct xl_heap_update
{
	TransactionId old_xmax;
	OffsetNumber old_offnum;
	uint8		old_infobits_set;
	uint8		flags;
	TransactionId new_xmax;
	OffsetNumber new_offnum;
} xl_heap_update;

typedef struct xl_heap_multi_insert
{
	uint8		flags;
	uint16		ntuples;
	OffsetNumber offsets[FLEXIBLE_ARRAY_MEMBER];
} xl_heap_multi_insert;

typedef struct TableModInfo
{
	Oid			relfilenode;
	int			num_operations;
	int			max_operations;
	WalOperation *operations;
} TableModInfo;

static TableModInfo *modified_tables = NULL;
static int num_modified_tables = 0;
static int max_modified_tables = 0;
static int WalSegSz = 16 * 1024 * 1024;	/* Default 16MB */

/* WAL reading context */
typedef struct WALDumpPrivate
{
	XLogRecPtr	startptr;
	XLogRecPtr	endptr;
	bool		endptr_reached;
	TimeLineID	timeline;
} WALDumpPrivate;

static int	WALDumpReadPage(XLogReaderState *state, XLogRecPtr targetPagePtr,
							int reqLen, XLogRecPtr targetPtr, char *readBuff);
static void WALDumpCloseSegment(XLogReaderState *state);
static void WALDumpOpenSegment(XLogReaderState *state, XLogSegNo nextSegNo,
							   TimeLineID *tli_p);
static int	count_total_operations(void);

static void
add_table_operation(Oid relfilenode, BlockNumber blkno, OffsetNumber offset,
					char op_type, uint32 xid)
{
	TableModInfo *table = NULL;
	int			i;

	for (i = 0; i < num_modified_tables; i++)
	{
		if (modified_tables[i].relfilenode == relfilenode)
		{
			table = &modified_tables[i];
			break;
		}
	}

	if (table == NULL)
	{
		if (num_modified_tables >= max_modified_tables)
		{
			max_modified_tables = max_modified_tables ? max_modified_tables * 2 : 10;
			modified_tables = pg_realloc(modified_tables,
										 max_modified_tables * sizeof(TableModInfo));
		}

		table = &modified_tables[num_modified_tables++];
		table->relfilenode = relfilenode;
		table->num_operations = 0;
		table->max_operations = 10;
		table->operations = pg_malloc(table->max_operations * sizeof(WalOperation));
	}

	if (table->num_operations >= table->max_operations)
	{
		table->max_operations *= 2;
		table->operations = pg_realloc(table->operations,
									table->max_operations * sizeof(WalOperation));
	}

	table->operations[table->num_operations].blkno = blkno;
	table->operations[table->num_operations].offset = offset;
	table->operations[table->num_operations].op_type = op_type;
	table->operations[table->num_operations].xid = xid;
	table->num_operations++;
}

/* WAL segment open callback */
static void
WALDumpOpenSegment(XLogReaderState *state, XLogSegNo nextSegNo, TimeLineID *tli_p)
{
	char		fname[MAXPGPATH];
	char		fpath[MAXPGPATH];

	XLogFileName(fname, *tli_p, nextSegNo, state->segcxt.ws_segsize);

	/* Build full path: waldir/filename */
	snprintf(fpath, MAXPGPATH, "%s/%s", state->segcxt.ws_dir, fname);

	/* Open from waldir (which points to saved_wal/) */
	state->seg.ws_file = open(fpath, O_RDONLY | PG_BINARY, 0);
	if (state->seg.ws_file >= 0)
	{
		state->seg.ws_segno = nextSegNo;
		state->seg.ws_tli = *tli_p;
		pg_log_debug("opened WAL segment %s (fd=%d)", fpath, state->seg.ws_file);
		return;
	}

	/* If not found, that's OK - we may have reached end of available WAL */
	pg_log_debug("could not open file \"%s\": %m", fpath);
}

/* WAL segment close callback */
static void
WALDumpCloseSegment(XLogReaderState *state)
{
	if (state->seg.ws_file >= 0)
		close(state->seg.ws_file);
	state->seg.ws_file = -1;
}

/* WAL page read callback */
static int
WALDumpReadPage(XLogReaderState *state, XLogRecPtr targetPagePtr, int reqLen,
				XLogRecPtr targetPtr, char *readBuff)
{
	WALDumpPrivate *private = state->private_data;
	int			count = XLOG_BLCKSZ;
	WALReadError errinfo;

	if (XLogRecPtrIsValid(private->endptr))
	{
		if (targetPagePtr + XLOG_BLCKSZ <= private->endptr)
			count = XLOG_BLCKSZ;
		else if (targetPagePtr + reqLen <= private->endptr)
			count = private->endptr - targetPagePtr;
		else
		{
			private->endptr_reached = true;
			return -1;
		}
	}

	pg_log_debug("reading WAL at %X/%X (reqLen=%d, count=%d)",
				 LSN_FORMAT_ARGS(targetPagePtr), reqLen, count);

	if (!WALRead(state, readBuff, targetPagePtr, count, private->timeline,
				 &errinfo))
	{
		WALOpenSegment *seg = &errinfo.wre_seg;
		char		fname[MAXPGPATH];

		XLogFileName(fname, seg->ws_tli, seg->ws_segno, state->segcxt.ws_segsize);

		if (errinfo.wre_errno != 0)
		{
			pg_log_debug("could not read from file \"%s\", offset %d: %s",
						 fname, errinfo.wre_off, strerror(errinfo.wre_errno));
		}
		else
		{
			pg_log_debug("could not read from file \"%s\", offset %d: read %d of %d",
						 fname, errinfo.wre_off, errinfo.wre_read, errinfo.wre_req);
		}
		return -1;
	}

	return count;
}

/*
 * Parse WAL records to find all heap operations with real block/offset
 */
void
analyze_wal_for_tables(const char *datadir, XLogRecPtr start_lsn, XLogRecPtr end_lsn, TimeLineID tli)
{
	XLogReaderState *xlogreader;
	WALDumpPrivate private;
	XLogRecord *record;
	char	   *errormsg = NULL;
	XLogRecPtr	first_record;
	char		waldir[MAXPGPATH];

	pg_log_info("parsing WAL records from %X/%X to %X/%X on timeline %u",
				LSN_FORMAT_ARGS(start_lsn),
				LSN_FORMAT_ARGS(end_lsn),
				tli);

	/* Initialize private data */
	private.startptr = start_lsn;
	private.endptr = end_lsn;
	private.endptr_reached = false;
	private.timeline = tli;

	/* Path to saved WAL directory */
	snprintf(waldir, MAXPGPATH, "%s/saved_wal", FORENSIC_OUTPUT_DIR);
	pg_log_info("using WAL directory: %s", waldir);

	/* Create XLogReader */
	xlogreader = XLogReaderAllocate(WalSegSz, waldir,
									XL_ROUTINE(.page_read = WALDumpReadPage,
											   .segment_open = WALDumpOpenSegment,
											   .segment_close = WALDumpCloseSegment),
									&private);
	if (!xlogreader)
	{
		pg_log_error("out of memory while allocating WAL reader");
		return;
	}

	/* Find first valid record */
	first_record = XLogFindNextRecord(xlogreader, start_lsn);
	if (first_record == InvalidXLogRecPtr)
	{
		pg_log_warning("could not find valid WAL record after %X/%X",
					   LSN_FORMAT_ARGS(start_lsn));
		XLogReaderFree(xlogreader);
		return;
	}

	/* Read and process WAL records */
	while (1)
	{
		record = XLogReadRecord(xlogreader, &errormsg);
		if (!record)
		{
			if (errormsg)
				pg_log_debug("WAL read error: %s", errormsg);
			break;
		}

		/* Check if we've reached the end LSN */
		if (xlogreader->EndRecPtr >= end_lsn)
			break;

		/* Process heap operations only */
		uint8		rmid = XLogRecGetRmid(xlogreader);	// HEAP / HEAP2 
		uint8		info = XLogRecGetInfo(xlogreader) & XLOG_HEAP_OPMASK;	// INSERT/DELETE/UPDATE 
		uint32		xid = XLogRecGetXid(xlogreader);

		if (rmid == RM_HEAP_ID)
		{
			/* Check if this record has block data */
			if (XLogRecHasBlockRef(xlogreader, 0))	// нужно дляполучения реального блока и оффсета
			{
				RelFileLocator rlocator;
				ForkNumber	forknum;
				BlockNumber blkno;

				if (!XLogRecGetBlockTagExtended(xlogreader, 0, &rlocator,
												&forknum, &blkno, NULL))
					continue;

				Oid relfilenode = rlocator.relNumber;

				if (info == XLOG_HEAP_INSERT)
				{
					xl_heap_insert *xlrec = (xl_heap_insert *) XLogRecGetData(xlogreader);
					
					add_table_operation(relfilenode, blkno, xlrec->offnum, 'I', xid);
					pg_log_debug("INSERT: rel=%u block=%u offset=%u xid=%u",
								 relfilenode, blkno, xlrec->offnum, xid);
				}
				else if (info == XLOG_HEAP_DELETE)
				{
					xl_heap_delete *xlrec = (xl_heap_delete *) XLogRecGetData(xlogreader);
					
					add_table_operation(relfilenode, blkno, xlrec->offnum, 'D', xid);
					pg_log_debug("DELETE: rel=%u block=%u offset=%u xid=%u",
								 relfilenode, blkno, xlrec->offnum, xid);
				}
				else if (info == XLOG_HEAP_UPDATE || info == XLOG_HEAP_HOT_UPDATE)
				{
					xl_heap_update *xlrec = (xl_heap_update *) XLogRecGetData(xlogreader);
					
					/* Use new tuple location */
					add_table_operation(relfilenode, blkno, xlrec->new_offnum, 'U', xid);
					pg_log_debug("UPDATE: rel=%u block=%u offset=%u xid=%u",
								 relfilenode, blkno, xlrec->new_offnum, xid);
				}
			}
		}
		else if (rmid == RM_HEAP2_ID)
		{
			if (info == XLOG_HEAP2_MULTI_INSERT && XLogRecHasBlockRef(xlogreader, 0))
			{
				RelFileLocator rlocator;
				ForkNumber	forknum;
				BlockNumber blkno;
				xl_heap_multi_insert *xlrec;
				int			i;

				if (!XLogRecGetBlockTagExtended(xlogreader, 0, &rlocator,
												&forknum, &blkno, NULL))
					continue;

				Oid relfilenode = rlocator.relNumber;
				xlrec = (xl_heap_multi_insert *) XLogRecGetData(xlogreader);

				/* Process each tuple in multi-insert */
				for (i = 0; i < xlrec->ntuples; i++)
				{
					add_table_operation(relfilenode, blkno, xlrec->offsets[i], 'I', xid);
					pg_log_debug("MULTI_INSERT[%d]: rel=%u block=%u offset=%u xid=%u",
								 i, relfilenode, blkno, xlrec->offsets[i], xid);
				}
			}
		}
	}

	XLogReaderFree(xlogreader);

	pg_log_info("WAL parsing complete: found %d modified tables",
				num_modified_tables);
}

int
get_modified_tables_count(void)
{
	return num_modified_tables;
}

void
get_modified_table_info(int index, Oid *relfilenode, int *num_ops, WalOperation **ops)
{
	if (index < 0 || index >= num_modified_tables)
		return;

	TableModInfo *table = &modified_tables[index];
	*relfilenode = table->relfilenode;
	*num_ops = table->num_operations;
	*ops = table->operations;
}

void
free_wal_analysis(void)
{
	int i;

	for (i = 0; i < num_modified_tables; i++)
	{
		if (modified_tables[i].operations)
			pg_free(modified_tables[i].operations);
	}

	if (modified_tables)
		pg_free(modified_tables);

	modified_tables = NULL;
	num_modified_tables = 0;
	max_modified_tables = 0;
}

static int
count_total_operations(void)
{
	int total = 0;
	int i;
	
	for (i = 0; i < num_modified_tables; i++)
		total += modified_tables[i].num_operations;
	
	return total;
}
