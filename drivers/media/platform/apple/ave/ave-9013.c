// SPDX-License-Identifier: GPL-2.0-only
/*
 * Apple video encoder (AVE): Start and Process for firmware 9013.55.1
 *
 * macOS 27.2's iBoot preloads AppleAVE2FW 9013.55.1, whose Start and Process
 * are rebuilt around new structures (AppleAVE2 27.2, its MakeFwCmd_Start_AVC
 * 0xfffffe0008dab0b4, Start_HEVC 0xfffffe0008dab82c, Process_AVC
 * 0xfffffe0008dae530, Process_HEVC 0xfffffe0008daece4):
 *
 *   Start    header, client and misc buffers, the buffer set (+0x68,
 *            AVE_CHM_SetFwBuf), then the session's settings as VideoToolbox
 *            gives them (copied by AVE_Client_Verify) and the parameter-set
 *            structures, the core map.
 *   Process  header, a parameter-set change (+0x48, zero here), the slice
 *            (+0x99c), and AVE_PICMGMT_PARAMS ("P"): its first 0x1810 bytes
 *            VideoToolbox's per-frame info, then the kext's copies of a few
 *            of its words, the frame's size, number and time, its buffers.
 *
 * The constant words are tables made from macOS 27.2.1's own calls (an
 * interposer on VideoToolbox's user client calls, 2026-11-23, as the 14.8.3
 * tables were made from a trace), with the kext's constant changes applied;
 * this file writes the words that follow the session and the frame.
 * Buffers are {u64 address; u32 size; u32 0} records
 * (AVE_Surface::GetDARTBuf 0xfffffe0008ec896c) after a count.
 *
 * One core encodes every frame, sequentially: the kext's mode with one
 * execution unit (AVE_Work_Enc_TuneParam's mode 0), so there is no SVERC
 * (AVE_MD_SVE::InitSVESequentialRC) and P's bitrate stays zero.
 *
 * What an H.264 key frame needs in P, from FW27's reads of it
 * (CAVCController::PipePrepareParam 0x7810, setPipe 0x635a0, setLRME
 * 0x61dac), each a fatal assert (bsp_assert_fail, then a spin) if missing:
 * the source, the coded data and header, the slice header's bits, the
 * reconstructed frame (sRecon, with compressed references), the
 * neighbours (this core's entry of each), the entropy buffers and the
 * low-res source (sLRInput, read by the in-pipe LRME every frame). An
 * I slice skips the reference loops (num_ref_idx_l0/l1_active_minus1
 * of -1) and so sRefColocated, the low-res references and sLRSOutput;
 * sColocated and sLFSOutput are used when set. sMBInputCtrl,
 * saMBStats and sMultiPassStats are read only under settings
 * (P+0x5ee bit 0, per-macroblock luma variance, multi-pass).
 *
 * Most of those the firmware writes into P itself: with the firmware's
 * rate control (settings+0x3fa bit 0, the kext's) and settings+0x578
 * bit 0 clear, PipePrepareParam runs ManageDPB, whose
 * CAVECommonDPB::setRefPointers (0xa650c) takes from its DPB the frame's
 * recon (y and its header; chroma at the DPB's own luma and header sizes
 * after them), sLRInput, sColocated, the references, sLFSOutput,
 * sLRSOutput, the neighbours and the entropy buffers, over what the host
 * wrote (only in the session mode 4 does it keep the host's sLRInput and
 * sLFSOutput; build 702 ran this path: its sLRInput came out zero).
 * CAVECommonDPB::ProvideReferenceFrames (0xa4ba8) fills that DPB at
 * Start from the buffer set: each DPB entry j (up to the kext's SPS
 * struct's max_num_ref_frames, +0x3a98 + 0x26) is the recon y and a at
 * +0x98/+0xa8 + 0x40j, saColocated[0][j], and the low-res buffer at
 * +0xfe8 + 0x40j, which the LRME writes the frame's downscaled source
 * into (CLRMEFSController::ConfigWrDMALowResSrcScaled 0x3a14c) and
 * later frames read as their low-res reference. v3 left that array
 * empty, so sLRInput came out zero: setLRME's assert at line 803.
 *
 * With cfg+0x7d set (the table's, as AVE_PSGen::Init sets it), FW27 builds
 * the SPS and PPS itself at Start (AVE_AVC_SPS/PPS::Generate) and puts
 * them in the first frame's coded header at +0xb1a8 (SetPSContext
 * 0x28088): a _S_AVE_PSContext, {count; {type, layer, offset, size}[21];
 * the NAL units with their start codes [0x800]}. macOS hands that to
 * VideoToolbox (AVE_Work_Enc_UpdateFrameInfoFromOutputData). Here they
 * replace the driver's own headers, kept for each key frame after.
 *
 * UNPINNED, each a bit of ave9_try where it can be tried (below) or left
 * as v2 had it (ave272-tables.md): the MCTF low-res array and the LRS
 * records in Start (macOS gives none at these settings); transcoded,
 * params, HEVC's extra buffers; the core map's pair; whether
 * VideoToolbox's settings ask for saMBStats; the scaled source; HEVC's
 * slice (+0x99c, FW27 WriteSliceHeadersHevc 0x46b40) and every
 * reference frame.
 */

#include <linux/math64.h>
#include <linux/moduleparam.h>
#include <linux/printk.h>
#include <linux/sizes.h>
#include <linux/unaligned.h>

#include "ave.h"
/* tables9013.py, from the avetap capture: the settings and per-frame words */
#include "ave-h264-tables-9013.h"
#include "ave-hevc-tables-9013.h"

/* Start: AVE_CHM_SetFwBuf (0xfffffe0008db4444), cmd offsets (the set is at +0x68) */
#define AVE9_CLIENT		0x48
#define AVE9_MISC		0x58
#define AVE9_DPB_SETS		0x90
#define AVE9_DPB_N		0x94
#define AVE9_DPB(j)		(0x98 + 0x40 * (j))	/* y, a, c, b (AVE_CHM_GetFwDPBBuf) */
#define AVE9_DPB_MAX		17
#define AVE9_CODED_N		0x918
#define AVE9_CODED(i)		(0x920 + 0x10 * (i))
#define AVE9_CODED_HDR_N	0xb00
#define AVE9_CODED_HDR(i)	(0xb08 + 0x10 * (i))
#define AVE9_CODED_MAX		30
#define AVE9_COLO_SETS		0xdb8
#define AVE9_COLO_N		0xdbc
#define AVE9_COLO(m)		(0xdc0 + 0x10 * (m))	/* saColocated[0][m] */
/*
 * The low-res buffers, one a DPB entry, [2][17] at 0x440 and 0x40:
 * {data, size, header, size}, the chroma half unused (SetFwBuf's stores,
 * AVE_CalcBufSizeOfLRB 0xfffffe0008da53d4: no header, luma only). FW27
 * reads the data address (ProvideReferenceFrames 0xa4ba8).
 */
#define AVE9_LRB_SETS		0xfe0
#define AVE9_LRB_N		0xfe4
#define AVE9_LRB(j)		(0xfe8 + 0x40 * (j))
/* saLFSOutput[]: the LRME's full-search results (setPipe's RDDMAMESFSRSLTS), a ring of 3 */
#define AVE9_LFS_N		0x1868
#define AVE9_LFS(i)		(0x1870 + 0x10 * (i))
#define AVE9_LFS_NUM		3
#define AVE9_NBR_INFO_N		0x19b8
#define AVE9_NBR_INFO		0x19c0
#define AVE9_NBR_PIXEL_N	0x1a00
#define AVE9_NBR_PIXEL		0x1a08
#define AVE9_NBR_DATA_N		0x1a48
#define AVE9_NBR_DATA		0x1a50
#define AVE9_NBR_FW_N		0x1a90
#define AVE9_NBR_FW		0x1a98
/*
 * saEntropyCoding[4][16] (K27 SetFwBuf's "pBufSet->saEntropyCoding[i][j]"):
 * set k, entry m (a pipe) {data, size, header, size}. The kext fills
 * AVE_CalcBufSetNumOfEntropyCoding's sets (2 with client+0x5f0 bit 0, else
 * 1) of AVE_CalcBufNumOfEntropyCoding's entries (4 per core for H.264), each
 * entry one surface: the header after the data, (height + 0x7f) & ~0x7f
 * bytes (AVE_CalcBufSizeOfEntropyCodingHeader). +0x1bb0 counts sets, +0x1bb4
 * entries (I: SetFwBuf's counters; no FW27 read of either was found).
 */
#define AVE9_ENTROPY_N		0x1bb0
#define AVE9_ENTROPY(k, m)	(0x1bb8 + 0x200 * (k) + 0x20 * (m))
#define AVE9_ENTROPY_SETS	4

/*
 * Start's settings (settings+N at +0x31f0 + N), as AVE_Client_Verify copies
 * them from VideoToolbox and FW27's ProcessCmd_Start (0xc0d40) reads them
 */
#define AVE9_SET		0x31f0
#define AVE9_SET_WIDTH		(AVE9_SET + 0x3c)	/* FW27 compares it with 0x1000 */
#define AVE9_SET_HEIGHT		(AVE9_SET + 0x40)	/* 16-aligned: 368 at 360 */
#define AVE9_SET_DEPTH		(AVE9_SET + 0x44)
#define AVE9_SET_HEIGHT2	(AVE9_SET + 0xb0)	/* the same, meaning not known */
#define AVE9_SET_FLAGS		(AVE9_SET + 0x3f8)	/* u64; bit 0 clear for Main 10 */
#define AVE9_SET_FPS		(AVE9_SET + 0x410)	/* iFrameRate (K27 AVE_Client_Enc_Print) */
#define AVE9_SET_BITRATE	(AVE9_SET + 0x428)	/* bit/s */
#define AVE9_SET_QP_OFF0	(AVE9_SET + 0x488)	/* -6 x (depth - 8) */
#define AVE9_SET_GOP		(AVE9_SET + 0x4f8)	/* MaxKeyFrameInterval */
#define AVE9_SET_QP_OFF1	(AVE9_SET + 0x550)
#define AVE9_SET_THROUGHPUT	(AVE9_SET + 0x570)	/* ThroughputMode (AVE_Client_Enc_PrintAVC) */

/* H.264's _S_AVE_Syntax_Cfg_AVC at +0x37b0: FW27 AVE_AVC_SetSPS (0x84104) reads it */
#define AVE9_AVC_CFG		0x37b0
#define AVE9_AVC_LEVEL		(AVE9_AVC_CFG + 0x8)	/* an index: AVC_FindLevelIdc 0x85efc */
#define AVE9_AVC_MBW		(AVE9_AVC_CFG + 0x22)	/* u16; the SPS takes it - 1 */
#define AVE9_AVC_MBH		(AVE9_AVC_CFG + 0x24)
#define AVE9_AVC_CROP		(AVE9_AVC_CFG + 0x50)	/* u8 frame_cropping_flag */
#define AVE9_AVC_CROP_R		(AVE9_AVC_CFG + 0x54)	/* u16s: left +0x52, right, top, bottom */
#define AVE9_AVC_CROP_B		(AVE9_AVC_CFG + 0x58)

/*
 * The kext's _S_AVC_SPS (0x60) at +0x3a98 and _S_AVC_PPS (0x1f) at
 * +0x3af8: PSGen::Init's AVE_AVC_SPS/PPS::Init run AVE_AVC_SetSPS and
 * AVE_AVC_SetPPS on cfg (K27 0xfffffe0008e490b8, 0xfffffe0008f05754, the
 * same code as FW27's 0x84104 and 0x832cc). FW27's InitEncodingParameters
 * copies both from the settings (+0x8a8, +0x908) and latches SPS fields at
 * once (0x1b520..0x1b5b0): the macroblock width and height (+0x28, +0x2a,
 * minus one) into the controller's for the whole session, the chroma
 * format (+0xc), the frame_num and POC lsb widths (+0x18, +0x1a), the
 * depth (+0x11), and later the DPB's reference count (+0x26,
 * ProvideReferenceFrames' second argument). Its rebuild from cfg comes
 * after all of these. Left zero, the session is a 1x1-macroblock picture:
 * build 703's register dump, 0x1110008 = 0x100010 where 80x45 gives
 * 0x2d00500.
 */
#define AVE9_AVC_SPS		0x3a98
#define AVE9_AVC_SPS_REFS	(AVE9_AVC_SPS + 0x26)	/* cfg+0x20 */
#define AVE9_AVC_PPS		0x3af8

/* HEVC: the video parameters at +0x37b4, the VPS at +0x3a20, the SPS at +0x64f0 */
#define AVE9_HEVC_VIDEO		0x37b4
#define AVE9_HEVC_VIDEO_DEPTH	(AVE9_HEVC_VIDEO + 0xc)
#define AVE9_HEVC_VIDEO_REFS	(AVE9_HEVC_VIDEO + 0x10)	/* u8 max num ref frames */
#define AVE9_HEVC_EDGE_REPL	(AVE9_HEVC_VIDEO + 0x3a)	/* u16 edgeReplEnable */
#define AVE9_HEVC_VPS		0x3a20
#define AVE9_HEVC_SPS		0x64f0
/* the profile, tier and level, at the same offsets of both (FW27 AVE_WritePTL 0x89680) */
#define AVE9_PTL_PROFILE	0x18	/* 1 Main, 2 Main 10: HEVC_FindProfileIdc */
#define AVE9_PTL_COMPAT1	0x1d	/* u8 general_profile_compatibility_flag[1] */
#define AVE9_PTL_8BIT		0x42	/* u8, 1 for Main only (I: max_8bit_constraint) */
#define AVE9_PTL_LEVEL		0x4c	/* an index: HEVC_FindLevelIdc 0x89458 */
#define AVE9_SPS_WIDTH		0x1c8
#define AVE9_SPS_HEIGHT		0x1cc
#define AVE9_SPS_CTBW		0x1d0
#define AVE9_SPS_CTBH		0x1d4
#define AVE9_SPS_CROP		0x1d8	/* u32 flag, then left, right, top, bottom */
#define AVE9_SPS_CROP_R		0x1e0
#define AVE9_SPS_CROP_B		0x1e8
#define AVE9_SPS_DEPTH		0x1ec	/* luma, chroma: depth - 8 */

/* Start's tail: FW27 ProcessCmd_Start (0xc0d40) */
#define AVE9_H264_OVERLAP	0x3b17	/* 14.8.3's +0x18a30, isOverlapPipeXcode */
#define AVE9_H264_EU		0x3b18	/* {u32 core index; u32 count; pairs[4]} */
#define AVE9_HEVC_OVERLAP	0x13eb0
#define AVE9_HEVC_EU		0x13eb4

/* Process: P is AVE_PICMGMT_PARAMS (0x6048 bytes) */
#define AVE9_H264_PS		0x48	/* 0x954 bytes, copied only when its first word is set */
#define AVE9_H264_SLICE		0x99c	/* _S_AVC_Slice */
#define AVE9_H264_P		0xdc0
#define AVE9_HEVC_P		0x1568
#define AVE9_HEVC_RPS		0x75b0	/* HEVC_RPS +0x5ac0, 14.8.3's +0x88f4 */

#define AVE9_P_FLAGS		0x0	/* u64; bit 0 the first frame (SetDataInfo_RC) */
#define AVE9_P_TYPE		0x48a0	/* the frame's type: setLRME's table 0x114b0c, 0 and 3 I, 1 P, 2 and 6 B */
/*
 * The frame's POC, FrameInfo+0x9a0: K27 AVE_DDPB::ManageDPBBuffer
 * (0xfffffe0008d82fc4) writes it as the frame number less the key frame's
 * (DPB+0xb78), VideoToolbox gives 0. FW27's CHEVCController::PipePrepareParam
 * (0x40430) and setLRME (0x72748) copy it to the frame's info (+0x24), which
 * AVE_HEVC_Update_POClsb_SliceType (0xdc970), SetRpsVars (0x3f024: the
 * RPS set from the POC less the key frame's) and calc_rps (0x3f8b8: the
 * references' POCs) read.
 */
#define AVE9_P_POC		0x48a8
#define AVE9_P_PADDED		0x1c28	/* FrameInfo+0x180d: HEVC's height padded */
#define AVE9_P_SIZE		0x4888	/* width, height: FrameInfo+0x14f0 (SetDataInfo_FwBuf) */
#define AVE9_P_FRAME		0x4890	/* u64; FW27 logs it as the frame's number */
#define AVE9_P_TIME		0x49a0	/* u64 time, u32 timescale: FrameInfo+0x1248 */
#define AVE9_P_TIMESCALE	0x49a8
#define AVE9_P_FRAME2		0x49f8
#define AVE9_P_INPUT		0x4a00	/* sInput: Y {addr, size, stride} +0, UV +0x20 */
#define AVE9_P_SCALED		0x4a80	/* pScaledSrc (K27's assert), linear; none: setLRME's mode 2 */
#define AVE9_P_CODED		0x4ae0	/* sCodedData */
#define AVE9_P_CODED_HDR	0x4af0	/* sCodedHeader */
#define AVE9_P_SLICE_HDR	0x4b00	/* sSliceHeader */
#define AVE9_P_SLICE_BITS	0x4b10	/* the bits' count (FW27 ConfigureMCPUs 0xa99c) */
#define AVE9_P_MBSTATS(m)	(0x4b18 + 0x10 * (m))	/* saMBStats: PipePrepareParam's 0x64d, 0x64e */
#define AVE9_P_RECON		0x4b38	/* sRecon: luma data, header, chroma data, header (setPipe) */
#define AVE9_P_COLO		0x4f78	/* sColocated: encoder_addr_dst_colo, unused when 0 */
#define AVE9_P_LR_INPUT		0x4f98	/* sLRInput: luma data, then the surface's base (K27) */
#define AVE9_P_LFS		0x51d8	/* sLFSOutput: setPipe's RDDMAMESFSRSLTS, unused when 0 */
#define AVE9_P_LRS		0x51e8	/* sLRSOutput: the reference loops' */
#define AVE9_P_NBR_INFO		0x51f8
#define AVE9_P_NBR_PIXEL	0x5238
#define AVE9_P_NBR_DATA		0x5278
#define AVE9_P_NBR_FW		0x52b8
#define AVE9_P_ENTROPY(k, m)	(0x53b8 + 0x200 * (k) + 0x20 * (m))	/* setRefPointers' copy of Start's */

/* FW27 GetSliceHeaderForFW maps this much of the bits' buffer; ProcessPipeStart asserts the size */
#define AVE9_SLICE_BITS_MAX	0x40

/* _S_AVC_Slice: the reference lists' sizes, -1 for none (setPipe's loops) */
#define AVE9_SLICE_OVERRIDE	0x32
#define AVE9_SLICE_L0		0x33
#define AVE9_SLICE_L1		0x34

/* The frame types FW27 takes at P+0x48a0 (I: 3 the IDR, as 14.8.3's trace had at its P+0x304c) */
#define AVE9_TYPE_IDR		3
#define AVE9_TYPE_I		0
#define AVE9_TYPE_P		1
/*
 * CFlowControllerBase::SendCommandToQueue (0xc1a8c) calls
 * CAVECommonController::GetFrameType only for types 5 and 7: its
 * CFrameType picks the type from the session's GOP and writes it over
 * P+0x48a0. Any other type is used as given.
 */
#define AVE9_TYPE_FW		5

/*
 * The coded header, CODED_DATA_HDR: FW27 maps 0xc7d0 bytes of it, the kext
 * allocates 0xd000 (AVE_CalcBufSizeOfCodedHeader)
 */
#define AVE9_HDR_FRAME		0xa8	/* FrameNumberFromDriverReturned (K27 0xfffffe0008f0a010) */
#define AVE9_HDR_TYPE		0xac	/* the frame's type as coded (I) */
#define AVE9_HDR_SLICES		0x118	/* FW27 CollectDataFromTranscode 0x1a19c: the count, */
#define AVE9_HDR_SLICE(i)	(0x11c + 0x10 * (i))	/* then {offset, size, 2 words} each */
#define AVE9_HDR_SLICES_MAX	32
#define AVE9_HDR_PS		0xb1a8	/* _S_AVE_PSContext (SetPSContext 0x28088) */
#define AVE9_PS_NUM_MAX		21	/* AVE_PSInfo_Make 0x85be0 */
#define AVE9_PS_INFO(i)		(4 + 0x10 * (i))	/* {type, layer, offset, size} */
#define AVE9_PS_DATA		0x154
#define AVE9_PS_DATA_SIZE	0x800

/*
 * The ladder: the bits of ave9_try (ave.h), most likely first. The main
 * session tries them in turn, one session each, as
 *   0, 0x100, 0x200, 0x80, 0x1, 0x4, 0x8
 * (rung 0 every choice's likeliest; 0x100 the control, v4's zero SPS
 * struct, which should hang as build 703 did; then one change each).
 * 0x10 changes only the output's headers and goes with any rung that
 * encodes. Each session boots the firmware again, so a rung whose frame
 * spins it costs its timeout.
 * Settled by build 702, kept only to repeat it: 0x2 (type 0 is an I
 * frame that is not an IDR, so the first frame's ManageDPBBuffer finds
 * no entry: "DPBGetFrameRequested:170", "ManageDPBBuffer:1539") and
 * 0x20 (setRefPointers takes sColocated from Start's array anyway).
 * 0x40 is retired: v5 writes the whole SPS struct by default.
 * HEVC P frames: 0x2000 (one reference, the POC), then 0x6000 (four
 * references) and 0x2400 (the firmware's frame types); without 0x2000
 * frame 1 is refused, as before.
 */
static unsigned int ave9_try;
module_param(ave9_try, uint, 0644);
MODULE_PARM_DESC(ave9_try,
		 "9013.55.1's variants, a mask: 0x1 saMBStats, 0x2 IDR type 0, 0x4 scaled source, 0x8 IOP clock, 0x10 own SPS/PPS, 0x20 no sColocated, 0x80 no LFS ring, 0x100 zero SPS/PPS structs, 0x200 one DPB entry, 0x400 firmware's frame type, 0x800 HEVC one reference, 0x1000 kext's entropy layout, 0x2000 HEVC P frames, 0x4000 with 0x2000: four references");

/* the firmware log's level a module (AVE_Log_Output: 3 errors and asserts, 4 warnings, 8 all) */
static unsigned int ave9_log_level = 5;
module_param_named(ave9_fwlog_level, ave9_log_level, uint, 0644);
MODULE_PARM_DESC(ave9_fwlog_level, "9013.55.1's log level a module, 0-8 (5)");

u32 ave9_try_mask(void)
{
	return READ_ONCE(ave9_try);
}

u32 ave9_fwlog_level(void)
{
	return min(READ_ONCE(ave9_log_level), 8U);
}

/*
 * The header's +0x30: VideoToolbox's timeout (118 s Start, 58 s Process),
 * which SendFwCmd_Start (0xfffffe0008e54280) and _Process (0xfffffe0008e57750)
 * scale by 8/10: 7060's 0x170c0 and 0xb540, a thousand times over
 */
#define AVE9_START_TIMEOUT	94400000
#define AVE9_PROCESS_TIMEOUT	46400000

/* VideoToolbox's time base for both codecs: FrameInfo+0x1250 */
#define AVE9_TIMESCALE		14400000

/* ThroughputMode as VideoToolbox picks it: 1 up to 1280x720, 3 at 1920x1080 (I: the step between) */
#define AVE9_THROUGHPUT_MBS	3600

static void ave9_put_ibuf(u8 *b, u32 off, dma_addr_t dva, u32 size)
{
	put_unaligned_le64(dva, b + off);
	put_unaligned_le32(size, b + off + 8);
	put_unaligned_le32(0, b + off + 12);
}

static void ave9_put_linear(u8 *b, u32 off, dma_addr_t src, u32 stride, u32 height)
{
	ave9_put_ibuf(b, off, src, stride * height);
	put_unaligned_le32(stride, b + off + 0xc);
	ave9_put_ibuf(b, off + 0x20, src + stride * height, stride * height / 2);
	put_unaligned_le32(stride, b + off + 0x2c);
}

/* One core: 14.8.3's traced map, a count of 1 and a zero pair */
static void ave9_put_eu(u8 *b, u32 off)
{
	memset(b + off, 0, 0x28);
	put_unaligned_le32(1, b + off + 4);
}

/* FW27's level tables (AVC 0x116d58, HEVC 0x117c00): the level's index from 1 */
static u32 ave9_level_index(const u8 *idcs, size_t n, u32 idc)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (idcs[i] == idc)
			return i + 1;
	return 0;
}

static const u8 ave9_avc_levels[] = {
	10, 10, 11, 12, 13, 20, 21, 22, 30, 31, 32, 40, 41, 42, 50, 51, 52, 60, 61, 62,
};

/* cfg+0x0's profile_idc: FW27 AVC_FindProfileIdc 0x86b88, its table at 0x1560d8 */
static const u8 ave9_avc_profiles[] = { 44, 66, 67, 77, 88, 100, 110, 122, 244 };

static u16 ave9_idc(const u8 *idcs, size_t n, u32 index)
{
	return index - 1 < n ? idcs[index - 1] : 0;
}

/*
 * The kext's SPS and PPS structs from the syntax configuration the
 * driver has written, as AVE_AVC_SetSPS (0x84104) and AVE_AVC_SetPPS
 * (0x832cc) make them; the bytes SetSPS leaves (+0x1c..+0x25, +0x2d)
 * stay zero. SPS+0x13 is bit 9 of the settings' first word (FW27 passes
 * its copy, InitEncodingParameters' this+0x1e238). FW27's level table
 * has 1 for index 2 (1b), which the driver's index never is.
 */
static void ave9_avc_put_sps_pps(u8 *b)
{
	const u8 *c = b + AVE9_AVC_CFG;
	u8 *sps = b + AVE9_AVC_SPS, *pps = b + AVE9_AVC_PPS;
	int i;

	put_unaligned_le16(ave9_idc(ave9_avc_profiles, ARRAY_SIZE(ave9_avc_profiles),
				    get_unaligned_le32(c)), sps);
	for (i = 0; i < 6; i++)
		sps[2 + i] = !!(c[4] & BIT(i));
	put_unaligned_le16(ave9_idc(ave9_avc_levels, ARRAY_SIZE(ave9_avc_levels),
				    get_unaligned_le32(c + 0x8)), sps + 0x8);
	sps[0xa] = c[0xc];
	memcpy(sps + 0xc, c + 0x10, 4);		/* chroma_format_idc */
	sps[0x10] = c[0x14];
	sps[0x11] = c[0x15] - 8;
	sps[0x12] = c[0x16] - 8;
	sps[0x13] = !!(get_unaligned_le32(b + AVE9_SET) & 0x200);
	memcpy(sps + 0x14, c + 0x18, 4);
	sps[0x18] = c[0x1c] - 4;
	sps[0x19] = c[0x1d];
	sps[0x1a] = c[0x1e] - 4;
	sps[0x1b] = c[0x1f];
	sps[0x26] = c[0x20];
	sps[0x27] = c[0x21];
	put_unaligned_le16(get_unaligned_le16(c + 0x22) - 1, sps + 0x28);
	put_unaligned_le16(get_unaligned_le16(c + 0x24) - 1, sps + 0x2a);
	sps[0x2c] = c[0x26];
	sps[0x2e] = c[0x27];
	sps[0x2f] = c[0x50];			/* frame_cropping_flag */
	memcpy(sps + 0x30, c + 0x52, 8);	/* crop left, right, top, bottom */
	memcpy(sps + 0x38, c + 0x28, 0x28);	/* the VUI */

	pps[0] = c[0xc];
	pps[1] = get_unaligned_le32(c + 0x5c) == 1;
	pps[2] = c[0x60];
	pps[3] = c[0x61] - 1;
	pps[4] = c[0x62] - 1;
	pps[5] = c[0x63] - 1;
	pps[6] = c[0x64];
	pps[7] = c[0x65];
	pps[8] = c[0x66] - 26;
	pps[9] = c[0x67] - 26;
	memcpy(pps + 0xa, c + 0x68, 0x15);
}

static const u8 ave9_hevc_levels[] = {
	30, 60, 63, 90, 93, 120, 123, 150, 153, 156, 180, 183, 186, 189, 210, 213, 216, 255,
};

/*
 * One entropy record. By default each set is build 704's set 0 (the second
 * buffer of each pipe as the header): the driver keeps one frame in
 * flight, so the sets never overlap. 0x1000 lays them out as the kext
 * does: two sets in turn, each entry one buffer, its header at the end.
 */
static void ave9_put_entropy(struct apple_ave_ctx *ctx, u8 *r, u32 set, u32 pipe)
{
	u32 hdr = ALIGN(ctx->height16, 0x80), data = ctx->entropy_size - hdr;
	dma_addr_t a = ctx->entropy[set & 1][pipe];

	if (ctx->try9 & AVE9_TRY_ENTROPY_KEXT) {
		ave9_put_ibuf(r, 0, a, data);
		ave9_put_ibuf(r, 0x10, a + data, hdr);
	} else {
		ave9_put_ibuf(r, 0, ctx->entropy[0][pipe], ctx->entropy_size);
		ave9_put_ibuf(r, 0x10, ctx->entropy[1][pipe], ctx->entropy_size);
	}
}

static void ave9_fill_start_buffers(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b)
{
	const struct ave_sizes *s = &ctx->sizes;
	u32 i, k;

	BUILD_BUG_ON(AVE_NUM_SLOTS > AVE9_DPB_MAX || AVE_NUM_SLOTS > AVE9_CODED_MAX);
	BUILD_BUG_ON(ARRAY_SIZE(ctx->lowres_result_ab) < AVE9_LFS_NUM);

	ave9_put_ibuf(b, AVE9_CLIENT, ctx->client, ave->client_size ?: AVE_DEFAULT_CLIENT_SIZE);
	ave9_put_ibuf(b, AVE9_MISC, ctx->misc, AVE_MISC_SIZE);

	/* one set of AVE_NUM_SLOTS frames, each one surface laid out a, b, y, c */
	put_unaligned_le32(1, b + AVE9_DPB_SETS);
	put_unaligned_le32(AVE_NUM_SLOTS, b + AVE9_DPB_N);
	for (i = 0; i < AVE_NUM_SLOTS; i++) {
		ave9_put_ibuf(b, AVE9_DPB(i) + 0x00, ctx->recon[i].y, s->rec_y);
		ave9_put_ibuf(b, AVE9_DPB(i) + 0x10, ctx->recon[i].a, s->rec_a);
		ave9_put_ibuf(b, AVE9_DPB(i) + 0x20, ctx->recon[i].c, s->rec_c);
		ave9_put_ibuf(b, AVE9_DPB(i) + 0x30, ctx->recon[i].b, s->rec_b);
	}

	put_unaligned_le32(AVE_NUM_SLOTS, b + AVE9_CODED_N);
	put_unaligned_le32(AVE_NUM_SLOTS, b + AVE9_CODED_HDR_N);
	for (i = 0; i < AVE_NUM_SLOTS; i++) {
		ave9_put_ibuf(b, AVE9_CODED(i), ctx->coded[i], ctx->coded_size);
		ave9_put_ibuf(b, AVE9_CODED_HDR(i), ctx->coded_hdr[i], AVE_CODED_HDR_SIZE);
	}

	put_unaligned_le32(1, b + AVE9_COLO_SETS);
	put_unaligned_le32(AVE_NUM_SLOTS, b + AVE9_COLO_N);
	for (i = 0; i < AVE_NUM_SLOTS; i++)
		ave9_put_ibuf(b, AVE9_COLO(i), ctx->colocated[i], s->colocated);

	/*
	 * Each DPB entry's low-res buffer, beside its recon and colocated:
	 * sLRInput of the frame that takes the entry, and its low-res
	 * reference after. AVE_CalcBufSizeOfLRB's size (device type 0x15,
	 * no header, luma data doubled) is 7060's lowres_ref at both codecs;
	 * the header record is the surface's base, 0 bytes, as SetFwBuf has it.
	 */
	put_unaligned_le32(1, b + AVE9_LRB_SETS);
	put_unaligned_le32(AVE_NUM_SLOTS, b + AVE9_LRB_N);
	for (i = 0; i < AVE_NUM_SLOTS; i++) {
		ave9_put_ibuf(b, AVE9_LRB(i), ctx->lowres_ref[i], s->lowres_ref);
		ave9_put_ibuf(b, AVE9_LRB(i) + 0x10, ctx->lowres_ref[i], 0);
	}

	/*
	 * The LFS ring (AVE_CalcBufSizeOfLFSOutput at device type 0x15: 7060's
	 * low-res results, unaligned). A P frame's sLFSOutput; an IDR takes
	 * none (ManageDPBBuffer's IDR path leaves it zero).
	 */
	if (!(ctx->try9 & AVE9_TRY_NO_LFS)) {
		u32 lfs = 4 * (((((ctx->mbw * 16 + 31) >> 5) * ((ctx->height16 + 63) >> 6)) << 7) +
			       0x400);

		put_unaligned_le32(AVE9_LFS_NUM, b + AVE9_LFS_N);
		for (i = 0; i < AVE9_LFS_NUM; i++)
			ave9_put_ibuf(b, AVE9_LFS(i), ctx->lowres_result_ab[i],
				      min(lfs, ctx->lowres_result_size));
	}
	dev_dbg(ctx->ave->dev, "9013 start: %u DPB entries, low-res %pad.. (%u bytes), LFS %pad%s\n",
		AVE_NUM_SLOTS, &ctx->lowres_ref[0], s->lowres_ref, &ctx->lowres_result_ab[0],
		ctx->try9 & AVE9_TRY_NO_LFS ? " not given" : "");

	put_unaligned_le32(1, b + AVE9_NBR_INFO_N);
	ave9_put_ibuf(b, AVE9_NBR_INFO, ctx->neighbor_info[0], s->info);
	put_unaligned_le32(1, b + AVE9_NBR_PIXEL_N);
	ave9_put_ibuf(b, AVE9_NBR_PIXEL, ctx->neighbor_pixel[0], s->pixel);
	put_unaligned_le32(1, b + AVE9_NBR_DATA_N);
	ave9_put_ibuf(b, AVE9_NBR_DATA, ctx->neighbor_data[0], s->data);
	put_unaligned_le32(1, b + AVE9_NBR_FW_N);
	ave9_put_ibuf(b, AVE9_NBR_FW, ctx->neighbor_fw[0], s->fw);

	/*
	 * Every set. setPipe (0x635a0) points the syntax-element writes
	 * (WrDMA 0x11303d0 + 0x40m) at entry m of set this+0x30f8, the
	 * command's +0x58, and PipePrepareParam (0x7c24) takes set k from set
	 * k when the command's +0x5c is set, from set 0 otherwise. Build 704
	 * gave set 0 only: the second Process wrote its syntax elements at 0
	 * (DART fault at 0, "CVE/SEB buffer write full", PIPE HANG).
	 */
	if (ctx->try9 & AVE9_TRY_ENTROPY_KEXT) {
		put_unaligned_le32(2, b + AVE9_ENTROPY_N);
		put_unaligned_le32(ctx->codec->pipes, b + AVE9_ENTROPY_N + 4);
	} else {
		put_unaligned_le32(ctx->codec->pipes, b + AVE9_ENTROPY_N);	/* build 704's */
	}
	for (k = 0; k < AVE9_ENTROPY_SETS; k++)
		for (i = 0; i < ctx->codec->pipes; i++)
			ave9_put_entropy(ctx, b + AVE9_ENTROPY(k, i), k, i);
	dev_dbg(ctx->ave->dev, "9013 start: entropy sets %u x %u, set 1 pipe 0 %#llx (%u bytes)%s\n",
		AVE9_ENTROPY_SETS, ctx->codec->pipes,
		get_unaligned_le64(b + AVE9_ENTROPY(1, 0)),
		get_unaligned_le32(b + AVE9_ENTROPY(1, 0) + 8),
		ctx->try9 & AVE9_TRY_ENTROPY_KEXT ? ", the kext's layout" : "");
}

/* The settings both codecs share: avetap's runs differ only in these */
static void ave9_put_settings(struct apple_ave_ctx *ctx, u8 *b)
{
	u32 mbs = ctx->mbw * ctx->mbh;

	/* I: 16-aligned as the height is; every captured width was a multiple of 16 */
	put_unaligned_le32(ctx->mbw * 16, b + AVE9_SET_WIDTH);
	put_unaligned_le32(ctx->height16, b + AVE9_SET_HEIGHT);
	put_unaligned_le32(ctx->height16, b + AVE9_SET_HEIGHT2);
	put_unaligned_le32(ave_fps(ctx), b + AVE9_SET_FPS);
	put_unaligned_le32(ctx->bitrate, b + AVE9_SET_BITRATE);
	/* FW27's AVE_KeyFrame takes 0x7fffffff for no limit (ProcessCmd_Start's engine-4 path) */
	put_unaligned_le32(ctx->gop_size ?: 0x7fffffff, b + AVE9_SET_GOP);
	put_unaligned_le32(mbs > AVE9_THROUGHPUT_MBS ? 3 : 1, b + AVE9_SET_THROUGHPUT);
}

static void ave9_h264_fill_start(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b)
{
	u32 crop_b = ctx->height16 - ctx->out_fmt.height;
	u32 crop_r = ctx->mbw * 16 - ctx->out_fmt.width;

	ave_put_words(b, ave9_h264_start_words, ARRAY_SIZE(ave9_h264_start_words));
	ave_cmd_header(ctx, ave, b, AVE_CMD_START, AVE_CMD_START, 0xc8, ctx->codec->x28_session,
		       AVE9_START_TIMEOUT);
	ave9_fill_start_buffers(ctx, ave, b);
	ave9_put_settings(ctx, b);

	/* the syntax configuration FW27 builds the SPS from: what 7060 took as SPS fields */
	put_unaligned_le32(ave9_level_index(ave9_avc_levels, ARRAY_SIZE(ave9_avc_levels),
					    ctx->level), b + AVE9_AVC_LEVEL);
	put_unaligned_le16(ctx->mbw, b + AVE9_AVC_MBW);
	put_unaligned_le16(ctx->mbh, b + AVE9_AVC_MBH);
	b[AVE9_AVC_CROP] = crop_b || crop_r;
	put_unaligned_le16(crop_r / 2, b + AVE9_AVC_CROP_R);
	put_unaligned_le16(crop_b / 2, b + AVE9_AVC_CROP_B);

	/*
	 * The kext's SPS and PPS structs, after every cfg write: two DPB
	 * entries with cfg+0x20's one reference (build 703's 0x40 gave them
	 * and logged no DPB error). 0x100 leaves both zero, v4's control;
	 * 0x200 keeps one entry, v4's default.
	 */
	if (!(ctx->try9 & AVE9_TRY_NO_SPS)) {
		ave9_avc_put_sps_pps(b);
		if (ctx->try9 & AVE9_TRY_ONE_REF)
			b[AVE9_AVC_SPS_REFS] = 0;
	}
	/* what InitEncodingParameters latches: 0x1110008 is these, << 2, in its dump */
	dev_dbg(ave->dev, "9013 start: SPS %ux%u macroblocks, chroma %u, %u refs\n",
		get_unaligned_le16(b + AVE9_AVC_SPS + 0x28) + 1,
		get_unaligned_le16(b + AVE9_AVC_SPS + 0x2a) + 1,
		get_unaligned_le32(b + AVE9_AVC_SPS + 0xc), b[AVE9_AVC_SPS_REFS]);

	b[AVE9_H264_OVERLAP] = 1;
	ave9_put_eu(b, AVE9_H264_EU);
}

static void ave9_hevc_put_ptl(struct apple_ave_ctx *ctx, u8 *ps)
{
	bool main10 = ctx->bit_depth > 8;

	put_unaligned_le32(main10 ? 2 : 1, ps + AVE9_PTL_PROFILE);
	ps[AVE9_PTL_COMPAT1] = !main10;
	ps[AVE9_PTL_8BIT] = !main10;
	put_unaligned_le32(ave9_level_index(ave9_hevc_levels, ARRAY_SIZE(ave9_hevc_levels),
					    ctx->level), ps + AVE9_PTL_LEVEL);
}

static void ave9_hevc_fill_start(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b)
{
	u32 w16 = ctx->mbw * 16, depth = ctx->bit_depth;
	u32 crop_r = w16 - ctx->out_fmt.width, crop_b = ctx->height16 - ctx->out_fmt.height;
	u8 *sps = b + AVE9_HEVC_SPS;

	/* the settings, video parameters, VPS, SPS, PPS; the RPS block 14.8.3's */
	ave_put_words(b, ave9_hevc_start_words, ARRAY_SIZE(ave9_hevc_start_words));
	ave_cmd_header(ctx, ave, b, AVE_CMD_START, AVE_CMD_START, 0xc8, ctx->codec->x28_session,
		       AVE9_START_TIMEOUT);
	ave9_fill_start_buffers(ctx, ave, b);
	ave9_put_settings(ctx, b);

	put_unaligned_le32(depth, b + AVE9_SET_DEPTH);
	put_unaligned_le32(depth, b + AVE9_HEVC_VIDEO_DEPTH);
	/*
	 * K27 AVE_PSGen::Init writes AVE_Work_Enc_CalcRefNum's count over
	 * VideoToolbox's 0 here (client+0x2110), and FW27's HEVC
	 * InitEncodingParameters passes it to ProvideReferenceFrames: 0 is
	 * one DPB entry, enough for key frames. CalcRefNum_Ext
	 * (0xfffffe0008f07d10) gives 1 at these settings (no B frames,
	 * settings+0x418 bit 6 clear, a key frame interval above 1; I: its
	 * client+0x227c and PSGen::Init's a6 taken as 0). 0x4000 gives 4, the
	 * firmware SPS's sps_max_dec_pic_buffering_minus1 and its RPS set 0.
	 */
	if (ctx->try9 & AVE9_TRY_HEVC_P)
		b[AVE9_HEVC_VIDEO_REFS] = ctx->try9 & AVE9_TRY_HEVC_REFS4 ? 4 : 1;
	else if (ctx->try9 & AVE9_TRY_HEVC_REFS)
		b[AVE9_HEVC_VIDEO_REFS] = 1;
	dev_dbg(ave->dev, "9013 start: HEVC references %u\n", b[AVE9_HEVC_VIDEO_REFS]);
	if (depth > 8) {
		b[AVE9_SET_FLAGS] &= ~1;
		put_unaligned_le32(-6 * (int)(depth - 8), b + AVE9_SET_QP_OFF0);
		put_unaligned_le32(-6 * (int)(depth - 8), b + AVE9_SET_QP_OFF1);
	}
	put_unaligned_le16(crop_b ? 10 : 0, b + AVE9_HEVC_EDGE_REPL);

	ave9_hevc_put_ptl(ctx, b + AVE9_HEVC_VPS);
	ave9_hevc_put_ptl(ctx, sps);
	put_unaligned_le32(w16, sps + AVE9_SPS_WIDTH);
	put_unaligned_le32(ctx->height16, sps + AVE9_SPS_HEIGHT);
	put_unaligned_le32((w16 + 31) >> 5, sps + AVE9_SPS_CTBW);
	put_unaligned_le32((ctx->height16 + 31) >> 5, sps + AVE9_SPS_CTBH);
	put_unaligned_le32(crop_r || crop_b, sps + AVE9_SPS_CROP);
	put_unaligned_le32(crop_r / 2, sps + AVE9_SPS_CROP_R);
	put_unaligned_le32(crop_b / 2, sps + AVE9_SPS_CROP_B);
	put_unaligned_le32(depth - 8, sps + AVE9_SPS_DEPTH);
	put_unaligned_le32(depth - 8, sps + AVE9_SPS_DEPTH + 4);

	b[AVE9_HEVC_OVERLAP] = 1;
	ave9_put_eu(b, AVE9_HEVC_EU);
}

/* The frame's words and buffers in P, both codecs */
static void ave9_fill_frame(struct apple_ave_ctx *ctx, u8 *p, dma_addr_t src)
{
	const struct v4l2_pix_format_mplane *out = &ctx->out_fmt;
	const struct ave_sizes *s = &ctx->sizes;
	u32 stride = out->plane_fmt[0].bytesperline, i, k;
	u32 slot = ctx->frame % AVE_USED_SLOTS, try = ctx->try9;
	const struct ave_recon *rec = &ctx->recon[slot];

	/* SetDataInfo_RC: the frame count below settings+0x68 (1) */
	if (!ctx->total)
		p[AVE9_P_FLAGS] |= 1;
	put_unaligned_le32(out->width, p + AVE9_P_SIZE);
	put_unaligned_le32(out->height, p + AVE9_P_SIZE + 4);
	put_unaligned_le64(ctx->total, p + AVE9_P_FRAME);
	put_unaligned_le64(ctx->total, p + AVE9_P_FRAME2);
	put_unaligned_le64(mul_u64_u32_div((u64)ctx->total * ctx->tpf.numerator, AVE9_TIMESCALE,
					   ctx->tpf.denominator), p + AVE9_P_TIME);
	put_unaligned_le32(AVE9_TIMESCALE, p + AVE9_P_TIMESCALE);

	/*
	 * The driver's own choice, which its slice bits follow: an IDR, or a
	 * P frame on the previous one (H264VideoEncoderDPB::ManageDPBBuffer
	 * 0xa757c takes the newest older entry of type <= 3, not 2, as L0)
	 */
	if (try & AVE9_TRY_FW_TYPE)
		put_unaligned_le32(AVE9_TYPE_FW, p + AVE9_P_TYPE);
	else if (ctx->frame)
		put_unaligned_le32(AVE9_TYPE_P, p + AVE9_P_TYPE);
	else
		put_unaligned_le32(try & AVE9_TRY_TYPE_I ? AVE9_TYPE_I : AVE9_TYPE_IDR,
				   p + AVE9_P_TYPE);

	/* K27 asserts both strides are multiples of 64 */
	ave9_put_linear(p, AVE9_P_INPUT, src, stride, out->height);
	if (try & AVE9_TRY_SCALED)
		ave9_put_linear(p, AVE9_P_SCALED, src, stride, out->height);

	/*
	 * This frame's reconstruction, planes as Start's DPB entry has them.
	 * Like the low-res buffers below, setRefPointers writes its own over
	 * it (the DPB's entry: 0 at an IDR); these stand only for a frame
	 * whose ManageDPBBuffer fails (and mode 4's low-res ones).
	 */
	ave9_put_ibuf(p, AVE9_P_RECON + 0x00, rec->y, s->rec_y);
	ave9_put_ibuf(p, AVE9_P_RECON + 0x10, rec->a, s->rec_a);
	ave9_put_ibuf(p, AVE9_P_RECON + 0x20, rec->c, s->rec_c);
	ave9_put_ibuf(p, AVE9_P_RECON + 0x30, rec->b, s->rec_b);
	if (!(try & AVE9_TRY_NO_COLO))
		ave9_put_ibuf(p, AVE9_P_COLO, ctx->colocated[slot], s->colocated);

	/*
	 * sLRInput is the DPB entry's low-res buffer (Start's +0xfe8 array),
	 * sLFSOutput and sLRSOutput the DPB's rings: an IDR gets none of the
	 * two, its LRME only writes the downscaled source to sLRInput
	 */
	ave9_put_ibuf(p, AVE9_P_LR_INPUT, ctx->lowres_ref[slot], s->lowres_ref);
	ave9_put_ibuf(p, AVE9_P_LR_INPUT + 0x10, ctx->lowres_ref[slot], s->lowres_ref);
	ave9_put_ibuf(p, AVE9_P_LFS, ctx->lowres_result[slot], ctx->lowres_result_size);
	ave9_put_ibuf(p, AVE9_P_LRS, ctx->lowres_result_ab[0], ctx->lowres_result_size);

	if ((try & AVE9_TRY_MBSTATS) && ctx->mbstats_size) {
		ave9_put_ibuf(p, AVE9_P_MBSTATS(0), ctx->mbstats[0], ctx->mbstats_size);
		ave9_put_ibuf(p, AVE9_P_MBSTATS(1), ctx->mbstats[1], ctx->mbstats_size);
	}

	ave9_put_ibuf(p, AVE9_P_CODED, ctx->coded[0], ctx->coded_size);
	ave9_put_ibuf(p, AVE9_P_CODED_HDR, ctx->coded_hdr[0], AVE_CODED_HDR_SIZE);

	ave9_put_ibuf(p, AVE9_P_NBR_INFO, ctx->neighbor_info[0], s->info);
	ave9_put_ibuf(p, AVE9_P_NBR_PIXEL, ctx->neighbor_pixel[0], s->pixel);
	ave9_put_ibuf(p, AVE9_P_NBR_DATA, ctx->neighbor_data[0], s->data);
	ave9_put_ibuf(p, AVE9_P_NBR_FW, ctx->neighbor_fw[0], s->fw);
	for (k = 0; k < AVE9_ENTROPY_SETS; k++)
		for (i = 0; i < ctx->codec->pipes; i++)
			ave9_put_entropy(ctx, p + AVE9_P_ENTROPY(k, i), k, i);

	dev_dbg(ctx->ave->dev,
		"9013 frame %u (try %#x): src %pad recon %pad/%pad lr %pad coded %pad hdr %pad\n",
		ctx->total, try, &src, &rec->y, &rec->a, &ctx->lowres_ref[slot], &ctx->coded[0],
		&ctx->coded_hdr[0]);
}

static void ave9_h264_fill_process(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b,
				   dma_addr_t src)
{
	u8 *p = b + AVE9_H264_P, *sl = b + AVE9_H264_SLICE;
	u32 n = ctx->frame, nbits;
	bool idr = !n;

	memset(b, 0, ctx->codec->process_size);
	/* P+0x568 and the kext's constant words of P+0x1810 and P+0x1c1c */
	ave_put_words(b, ave9_h264_process_words, ARRAY_SIZE(ave9_h264_process_words));
	ave_cmd_header(ctx, ave, b, AVE_CMD_PROCESS, 0x15, 0, ctx->codec->x28_frame,
		       AVE9_PROCESS_TIMEOUT);
	put_unaligned_le32(0, b + AVE9_H264_PS);	/* no parameter-set change */

	/* _S_AVC_Slice: FW27 GetSliceHeaderForFW 0xbf40, AVC_Slice::Write_slice_header 0x86f10 */
	put_unaligned_le32(1, sl + 0x0);		/* nal_ref_idc */
	put_unaligned_le32(idr ? 5 : 1, sl + 0x4);	/* nal_unit_type */
	put_unaligned_le32(0, sl + 0x8);		/* first_mb_in_slice */
	put_unaligned_le32(idr ? 2 : 0, sl + 0xc);	/* slice_type */
	put_unaligned_le32(n & 0x1f, sl + 0x14);	/* frame_num: cfg+0x1c, log2 5 */
	put_unaligned_le32(ctx->idr_id, sl + 0x1c);	/* idr_pic_id */
	put_unaligned_le32(n, sl + 0x20);		/* pic_order_cnt_lsb, as 14.8.3 got it */
	/*
	 * The reference lists' sizes - 1: setPipe (0x635a0) runs its l0 loop
	 * while +0x33 >= 0, its l1 loop while +0x34 >= 0, each asserting the
	 * reference's recon and sLFSOutput, which setRefPointers fills from
	 * the DPB (7060's +0x8c, l0, was -1 at an IDR too). A P frame has
	 * one, the PPS's default (num_ref_idx_l0_default_active_minus1 = 0).
	 */
	sl[AVE9_SLICE_OVERRIDE] = 0;
	sl[AVE9_SLICE_L0] = idr ? 0xff : 0;
	sl[AVE9_SLICE_L1] = 0xff;

	/* the bits from slice_type to the deblocking, in a buffer now */
	memset(ctx->slice_bits.cpu, 0, AVE9_SLICE_BITS_MAX);
	ave_h264_slice_bits(ctx, ctx->slice_bits.cpu, &nbits, idr);
	ave9_put_ibuf(p, AVE9_P_SLICE_HDR, ctx->slice_bits.dva, AVE9_SLICE_BITS_MAX);
	put_unaligned_le32(nbits, p + AVE9_P_SLICE_BITS);

	ave9_fill_frame(ctx, p, src);
}

static void ave9_hevc_fill_process(struct apple_ave_ctx *ctx, struct apple_ave *ave, u8 *b,
				   dma_addr_t src)
{
	u8 *p = b + AVE9_HEVC_P;
	bool idr = !ctx->frame;

	memset(b, 0, ctx->codec->process_size);
	/*
	 * VideoToolbox's slice (+0x99c), P+0x568, and the kext's constant
	 * P+0x1c1c, +0x1c2c, +0x49e0. K27 HEVC_Slice::Generate
	 * (0xfffffe0008f358d8) rewrites the slice each frame, but FW27 does the
	 * same over it: with the firmware's rate control (settings+0x3fa bit
	 * 0, the kext's TuneParam) its PipePrepareParam (0x40430) or, asynchronous,
	 * setLRME (0x72748) runs AVE_HEVC_Update_POClsb_SliceType, SetRpsVars,
	 * calc_rps, ManageDPB and AVE_HEVC_PrepareSliceHeader (0xdcaec), which
	 * write the NAL and slice types, POC lsb, the reference counts (the
	 * DPB's L0 entries, cut to calc_rps' NumPicTotalCurr), the QP delta,
	 * the override flag, the RPS index and the MVP fields
	 * (program_mvp_fw_regs 0xdd678) from the frame's type, POC and DPB.
	 * The rest Generate writes comes from FrameInfo words VideoToolbox's
	 * P frames leave as the table has them (+0x3a7, +0xa, +0x114, +0x19c).
	 */
	ave_put_words(b, ave9_hevc_process_words, ARRAY_SIZE(ave9_hevc_process_words));
	ave_cmd_header(ctx, ave, b, AVE_CMD_PROCESS, 0x15, 0, ctx->codec->x28_frame,
		       AVE9_PROCESS_TIMEOUT);
	put_unaligned_le32(0, b + AVE9_H264_PS);

	/* the firmware writes the slice headers here (I: one buffer for 14.8.3's 256 pointers) */
	ave9_put_ibuf(p, AVE9_P_SLICE_HDR, ctx->slice_hdr.dva, ctx->codec->slice_hdr_size);
	/* VideoToolbox's FrameInfo+0x180d, set at 360 and 1080 lines: 14.8.3's +0x5c30 */
	p[AVE9_P_PADDED] = ctx->height16 != ctx->out_fmt.height;

	/*
	 * HEVC_RPS, moved whole (I): num_negative_pics, and 14.8.3's +0x8954.
	 * FW27 copies these 0x314 bytes per frame, then SetRpsVars writes its
	 * +0 (the SPS set flag) and +4 (the set) and calc_rps reads the SPS's
	 * set, or its own program_sh_rps_hierarchical's (I: these two words read
	 * by neither).
	 */
	put_unaligned_le32(!idr, b + AVE9_HEVC_RPS + 0x38);
	put_unaligned_le32(!!ctx->total, b + AVE9_HEVC_RPS + 0x60);
	if (ctx->try9 & AVE9_TRY_HEVC_P) {
		put_unaligned_le32(ctx->frame, p + AVE9_P_POC);
		dev_dbg(ave->dev, "9013 HEVC frame %u: POC %u\n", ctx->total, ctx->frame);
	}

	ave9_fill_frame(ctx, p, src);
}

/* The firmware's SPS and PPS, in the first frame's coded header */
static void ave9_take_ps(struct apple_ave_ctx *ctx, u8 *ps)
{
	struct device *dev = ctx->ave->dev;
	u32 num = get_unaligned_le32(ps), end = 0, i;

	if (!num)
		return;
	if (num > AVE9_PS_NUM_MAX) {
		dev_err(dev, "frame %u: %u parameter sets in the coded header\n", ctx->total, num);
		goto out;
	}
	for (i = 0; i < num; i++) {
		const u8 *e = ps + AVE9_PS_INFO(i);
		u32 off = get_unaligned_le32(e + 8), size = get_unaligned_le32(e + 12);

		dev_dbg(dev, "fw parameter set %u: type %u layer %u, %u bytes at %u\n", i,
			get_unaligned_le32(e), get_unaligned_le32(e + 4), size, off);
		end = max(end, off + size);
	}
	print_hex_dump_debug("ave9 ps: ", DUMP_PREFIX_OFFSET, 16, 1, ps + AVE9_PS_DATA,
			     min_t(u32, end, AVE9_PS_DATA_SIZE), false);
	if (end > AVE9_PS_DATA_SIZE || end > sizeof(ctx->headers)) {
		dev_warn(dev, "the firmware's parameter sets take %u bytes: the driver's kept\n", end);
	} else if (!(ctx->try9 & AVE9_TRY_OWN_PS)) {
		memcpy(ctx->headers, ps + AVE9_PS_DATA, end);
		ctx->headers_len = end;
		dev_dbg(dev, "the firmware's SPS and PPS (%u bytes) replace the driver's\n", end);
	}
out:
	put_unaligned_le32(0, ps);
}

/*
 * The frame's bytes in the coded data: FW27 writes each slice's offset and
 * size (CollectDataFromTranscode); the parameter sets apart, at +0xb1a8
 */
/*
 * P's buffer words after the frame, done or not: if FW27 works on the
 * command in place, setRefPointers' values show here instead of the
 * driver's (an IDR's sLFSOutput 0, its size Start's LFS[0]; the recon's
 * chroma minus luma the firmware's luma size). If they read as written,
 * the firmware works on a copy.
 */
void ave9_p_readback(struct apple_ave_ctx *ctx)
{
	u32 off = ctx->codec == &ave_codec_hevc_9013 ? AVE9_HEVC_P : AVE9_H264_P;
	const u8 *p = ctx->process[ctx->ave->instance] + off;

	dev_dbg(ctx->ave->dev,
		"frame %u: P after: recon %#llx/%#llx, chroma %#llx/%#llx, colo %#llx, lr %#llx, lfs %#llx (%u), lrs %#llx\n",
		ctx->total, get_unaligned_le64(p + AVE9_P_RECON),
		get_unaligned_le64(p + AVE9_P_RECON + 0x10),
		get_unaligned_le64(p + AVE9_P_RECON + 0x20),
		get_unaligned_le64(p + AVE9_P_RECON + 0x30), get_unaligned_le64(p + AVE9_P_COLO),
		get_unaligned_le64(p + AVE9_P_LR_INPUT), get_unaligned_le64(p + AVE9_P_LFS),
		get_unaligned_le32(p + AVE9_P_LFS + 8), get_unaligned_le64(p + AVE9_P_LRS));
}

int ave9_frame_done(struct apple_ave_ctx *ctx, u32 *start, u32 *bytes)
{
	struct device *dev = ctx->ave->dev;
	u8 *h = ctx->coded_hdr0.cpu;
	u32 n, i, end = 0;

	ave9_p_readback(ctx);
	ave9_take_ps(ctx, h + AVE9_HDR_PS);

	n = get_unaligned_le32(h + AVE9_HDR_SLICES);
	dev_dbg(dev, "frame %u: coded header's frame %u, type %u, %u slices\n", ctx->total,
		get_unaligned_le32(h + AVE9_HDR_FRAME), get_unaligned_le32(h + AVE9_HDR_TYPE), n);
	if (!n || n > AVE9_HDR_SLICES_MAX)
		goto bad;
	*start = get_unaligned_le32(h + AVE9_HDR_SLICE(0));
	for (i = 0; i < n; i++) {
		u32 off = get_unaligned_le32(h + AVE9_HDR_SLICE(i));
		u32 size = get_unaligned_le32(h + AVE9_HDR_SLICE(i) + 4);

		dev_dbg(dev, "  slice %u: %u bytes at %u\n", i, size, off);
		if (i && off != end)
			dev_dbg(dev, "  slice %u does not follow slice %u\n", i, i - 1);
		end = off + size;
	}
	if (end <= *start || end > ctx->coded_size)
		goto bad;
	*bytes = end - *start;
	print_hex_dump_debug("ave9 coded: ", DUMP_PREFIX_OFFSET, 16, 1, ctx->coded0.cpu + *start,
			     min_t(u32, *bytes, 32), false);
	memset(h, 0, AVE9_HDR_SLICE(AVE9_HDR_SLICES_MAX));
	return 0;

bad:
	dev_err(dev, "frame %u: %u slices, bytes %u to %u of %u: not a frame\n", ctx->total, n,
		*start, end, ctx->coded_size);
	print_hex_dump_debug("ave9 coded header: ", DUMP_PREFIX_OFFSET, 16, 4, h,
			     AVE9_HDR_SLICE(4), false);
	ave9_fwlog_print(ctx->ave);
	return -EPROTO;
}

const struct ave_codec ave_codec_h264_9013 = {
	.id = 1,
	.start_size = 0x3b40,
	.process_size = 0x6e08,
	.x28_session = 0x50,	/* the pipes' mask: same bits (I) */
	.x28_frame = 0x70,
	.session_flags = AVE9_H264_SESSION_FLAGS,
	.pipes = 4,
	.slice_bits_size = SZ_16K,
	.layout = ave_h264_layout,
	.sizes = ave_h264_sizes,
	.fill_start = ave9_h264_fill_start,
	.fill_process = ave9_h264_fill_process,
};

const struct ave_codec ave_codec_hevc_9013 = {
	.id = 2,
	.start_size = 0x13ee0,
	.process_size = 0x78c8,
	.x28_session = 0x8,
	.x28_frame = 0x68,
	.session_flags = AVE9_HEVC_SESSION_FLAGS,
	.pipes = 2,
	.slice_hdr_size = AVE_SLICE_HDR_STRIDE * AVE_SLICE_HDR_NUM,
	.layout = ave_hevc_layout,
	.sizes = ave_hevc_sizes,
	.fill_start = ave9_hevc_fill_start,
	.fill_process = ave9_hevc_fill_process,
};
