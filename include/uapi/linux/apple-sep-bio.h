/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Touch ID on Apple silicon through the SEP: /dev/apple-sep-bio (drivers/soc/apple/sep, bio.rs).
 *
 * The SEP matches; the host keeps only what the SEP seals for it (each component's catacomb and the lockout
 * record) and hands it back after a restart with LOAD. One opener at a time; one operation at a time.
 *
 * An operation: ENROL or MATCH, then CAPTURE once per touch until a result ends it, then END. END leaves a save:
 * SAVE_NEXT hands each record to keep (the catacombs, then the lockout record), SAVE_CONFIRM once it is on the
 * disk. No other operation starts before the save is done. CANCEL may come from another thread at any time.
 */
#ifndef _UAPI_LINUX_APPLE_SEP_BIO_H
#define _UAPI_LINUX_APPLE_SEP_BIO_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define APPLE_SEP_BIO_VERSION 3
#define APPLE_SEP_BIO_UUID_LEN 16
#define APPLE_SEP_BIO_LIST_MAX 16
#define APPLE_SEP_BIO_BLOB_MAX 0x500000
#define APPLE_SEP_BIO_BAG_MAX 0x4000

/* apple_sep_bio_info.state */
#define APPLE_SEP_BIO_READY 1	/* the session unlocked and the sensor calibrated: operations may run */
#define APPLE_SEP_BIO_OPS 2	/* ENROL, MATCH and the save are open */
#define APPLE_SEP_BIO_UNLOCKED 4	/* a user's session is unlocked: UNLOCK done, or the lab's identity file */

struct apple_sep_bio_info {
	__u32 version;		/* APPLE_SEP_BIO_VERSION */
	__u32 state;
	__u32 sensor_id;	/* 0x3352 on the M3 MacBook Pros */
	__u32 reserved[5];
};

/* apple_sep_bio_blob.kind */
#define APPLE_SEP_BIO_CATACOMB 1	/* a component's sealed catacomb; its header names the component at 8 */
#define APPLE_SEP_BIO_LOCKOUT 2		/* the lockout record */

struct apple_sep_bio_blob {
	__u32 kind;
	__s32 component;	/* a catacomb's user: -1 the system's */
	__u32 len;		/* LOAD: 1 to BLOB_MAX; SAVE_NEXT: in the buffer's size, out the record's */
	__u32 status;		/* out: the SEP's answer, 0 taken */
	__u64 data;		/* a pointer to len bytes */
};

struct apple_sep_bio_identity {
	__u32 uid;
	__u8 uuid[APPLE_SEP_BIO_UUID_LEN];
};

struct apple_sep_bio_list {
	__u32 uid;		/* in */
	__u32 status;		/* out: the SEP's answer */
	__u32 count;		/* out: the user's identities in the SEP; at most LIST_MAX are given */
	__u32 reserved;
	struct apple_sep_bio_identity id[APPLE_SEP_BIO_LIST_MAX];
};

/*
 * UNLOCK: the user's identity, once a boot, which unlocks their session in the SEP. bag_len 0 asks the SEP to make
 * the wrapped bag: it comes back in bag (a BAG_MAX buffer) with its length in bag_len, to keep with the identity and
 * give back after a restart. The identity is the caller's to keep secret.
 */
struct apple_sep_bio_unlock {
	__u32 uid;		/* 10 or more */
	__u32 bag_len;		/* in: the kept bag's, 0 to make one; out: the new bag's */
	__u8 uuid[APPLE_SEP_BIO_UUID_LEN];
	__u8 secret[32];
	__u64 bag;		/* a pointer: the kept bag, or a BAG_MAX buffer for the new one */
};

/* apple_sep_bio_begin.flags, MATCH only */
#define APPLE_SEP_BIO_MATCH_UNLOCK 0x1	/* BKOptionMatchForUnlock */

struct apple_sep_bio_begin {
	__u32 uid;		/* the user enrolled or matched; their component must be loaded for a match */
	__u32 flags;
	__u32 reserved[2];
};

/* apple_sep_bio_capture.result */
#define APPLE_SEP_BIO_NO_FINGER 1	/* no finger within timeout_ms: CAPTURE again or END */
#define APPLE_SEP_BIO_RETRY 2		/* an image the SEP did not use (feedback): another touch */
#define APPLE_SEP_BIO_ENROL_STEP 3	/* an image the enrolment used (progress): another touch */
#define APPLE_SEP_BIO_ENROL_DONE 4	/* the enrolment complete: END, the save, then LIST for its UUID */
#define APPLE_SEP_BIO_MATCHED 5		/* the SEP named an identity (uid, uuid): END */
#define APPLE_SEP_BIO_NO_MATCH 6	/* a usable image matched no identity: another touch */
#define APPLE_SEP_BIO_CANCELLED 7	/* CANCEL: END */
#define APPLE_SEP_BIO_FAILED 8		/* the SEP refused a step (status): END */

struct apple_sep_bio_capture {
	__u32 timeout_ms;	/* in: 1 to 120000 */
	__u32 result;		/* out */
	__u32 progress;		/* out, ENROL_STEP: the SEP's progress */
	__u32 feedback;		/* out, RETRY: the SEP's feedback on the image */
	__u32 status;		/* out, FAILED: the SEP's answer when a step gave one, else 0 */
	__u32 uid;		/* out, MATCHED */
	__u8 uuid[APPLE_SEP_BIO_UUID_LEN];
	__u32 reserved[2];
};

#define APPLE_SEP_BIO_IOC 0xB9
#define APPLE_SEP_BIO_GET_INFO _IOR(APPLE_SEP_BIO_IOC, 0x00, struct apple_sep_bio_info)
/*
 * A catacomb goes to the SEP only when it does not show its component active (EALREADY otherwise), or once more
 * after its refusal. Its answer is in status: 0 taken; 0x8002, 0x8003 or 0x192 refused as corrupted, the component
 * then active and empty.
 */
#define APPLE_SEP_BIO_LOAD _IOWR(APPLE_SEP_BIO_IOC, 0x01, struct apple_sep_bio_blob)
#define APPLE_SEP_BIO_LIST _IOWR(APPLE_SEP_BIO_IOC, 0x02, struct apple_sep_bio_list)
/*
 * For the user the identity file or UNLOCK names (EINVAL otherwise). EBUSY while an operation or a save is open; ENOENT, MATCH,
 * when the user's component is not loaded. LOAD a kept catacomb before an ENROL: an enrolment into a component not
 * loaded starts it anew, and its save replaces the kept one.
 */
#define APPLE_SEP_BIO_ENROL _IOW(APPLE_SEP_BIO_IOC, 0x03, struct apple_sep_bio_begin)
#define APPLE_SEP_BIO_MATCH _IOW(APPLE_SEP_BIO_IOC, 0x04, struct apple_sep_bio_begin)
/* blocks until a result; EINVAL without an operation or after one that ended it */
#define APPLE_SEP_BIO_CAPTURE _IOWR(APPLE_SEP_BIO_IOC, 0x05, struct apple_sep_bio_capture)
/* an unfinished enrolment is cancelled; the sensor goes off; the save opens */
#define APPLE_SEP_BIO_END _IO(APPLE_SEP_BIO_IOC, 0x06)
/*
 * The next record to keep, the same one until it is confirmed; ENOSPC with len the size it needs (a BLOB_MAX buffer
 * always fits); ENODATA when no save is open. The save ends with the lockout record's confirm.
 */
#define APPLE_SEP_BIO_SAVE_NEXT _IOWR(APPLE_SEP_BIO_IOC, 0x07, struct apple_sep_bio_blob)
#define APPLE_SEP_BIO_SAVE_CONFIRM _IO(APPLE_SEP_BIO_IOC, 0x08)
#define APPLE_SEP_BIO_CANCEL _IO(APPLE_SEP_BIO_IOC, 0x09)
/* EALREADY after one this boot; ENOTTY below the driver's stage 17; EIO when the SEP refused a step (the identity is
 * then spent until a reboot) */
#define APPLE_SEP_BIO_UNLOCK _IOWR(APPLE_SEP_BIO_IOC, 0x0a, struct apple_sep_bio_unlock)

#endif /* _UAPI_LINUX_APPLE_SEP_BIO_H */
