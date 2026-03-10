
#ifndef FORENSIC_DECODE_H
#define FORENSIC_DECODE_H

#include "access/xlogdefs.h"

/*
 * This function performs forensic analysis of WAL between divergence
 * point and target's end LSN. It saves decoded changes to a file
 * for audit/recovery purposes.
 */
extern void perform_forensic_decode(const char *target_datadir,
									 XLogRecPtr start_lsn, XLogRecPtr end_lsn,
									 TimeLineID target_tli);

#endif							/* FORENSIC_DECODE_H */
