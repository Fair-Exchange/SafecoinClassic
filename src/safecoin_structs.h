/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "safecoin_defs.h"

#include "uthash.h"
#include "utlist.h"

/*#ifdef _WIN32
#define PACKED
#else
#define PACKED __attribute__((packed))
#endif*/

#ifndef SAFECOIN_STRUCTS_H
#define SAFECOIN_STRUCTS_H

#define GENESIS_NBITS 0x1f00ffff
#define SAFECOIN_MINRATIFY ((height < 90000) ? 7 : 11)
#define SAFECOIN_NOTARIES_HARDCODED 1 // DONT CHANGE
#define SAFECOIN_MAXBLOCKS 250000 // DONT CHANGE

#define SAFECOIN_EVENT_RATIFY 'P'
#define SAFECOIN_EVENT_NOTARIZED 'N'
#define SAFECOIN_EVENT_SAFEHEIGHT 'K'
#define SAFECOIN_EVENT_REWIND 'B'
#define SAFECOIN_EVENT_PRICEFEED 'V'
#define SAFECOIN_EVENT_OPRETURN 'R'
#define SAFECOIN_OPRETURN_DEPOSIT 'D'
#define SAFECOIN_OPRETURN_ISSUED 'I' // assetchain
#define SAFECOIN_OPRETURN_WITHDRAW 'W' // assetchain
#define SAFECOIN_OPRETURN_REDEEMED 'X'

#define SAFECOIN_KVPROTECTED 1
#define SAFECOIN_KVBINARY 2
#define SAFECOIN_KVDURATION 1440
#define SAFECOIN_ASSETCHAIN_MAXLEN 65

#ifndef _BITS256
#define _BITS256
    union _bits256 { uint8_t bytes[32]; uint16_t ushorts[16]; uint32_t uints[8]; uint64_t ulongs[4]; uint64_t txid; };
    typedef union _bits256 bits256;
#endif

union _bits320 { uint8_t bytes[40]; uint16_t ushorts[20]; uint32_t uints[10]; uint64_t ulongs[5]; uint64_t txid; };
typedef union _bits320 bits320;

struct safecoin_kv { UT_hash_handle hh; bits256 pubkey; uint8_t *key,*value; int32_t height; uint32_t flags; uint16_t keylen,valuesize; };

struct safecoin_event_notarized { uint256 blockhash,desttxid,MoM; int32_t notarizedheight,MoMdepth; char dest[16]; };
struct safecoin_event_pubkeys { uint8_t num; uint8_t pubkeys[64][33]; };
struct safecoin_event_opreturn { uint256 txid; uint64_t value; uint16_t vout,oplen; uint8_t opret[]; };
struct safecoin_event_pricefeed { uint8_t num; uint32_t prices[35]; };

struct safecoin_event
{
    struct safecoin_event *related;
    uint16_t len;
    int32_t height;
    uint8_t type,reorged;
    char symbol[SAFECOIN_ASSETCHAIN_MAXLEN];
    uint8_t space[];
};

struct pax_transaction
{
    UT_hash_handle hh;
    uint256 txid;
    uint64_t safecoinshis,fiatoshis,validated;
    int32_t marked,height,otherheight,approved;
    bool ready,didstats;
    uint16_t vout;
    char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],source[SAFECOIN_ASSETCHAIN_MAXLEN],coinaddr[64]; uint8_t rmd160[20],type,buf[35];
};

struct knotary_entry { UT_hash_handle hh; uint8_t pubkey[33],notaryid; };
struct knotaries_entry { int32_t height,numnotaries; struct knotary_entry *Notaries; };
struct notarized_checkpoint
{
    uint256 notarized_hash,notarized_desttxid,MoM,MoMoM;
    int32_t nHeight,notarized_height,MoMdepth,MoMoMdepth,MoMoMoffset,safestarti,safeendi;
};

struct safecoin_ccdataMoM
{
    uint256 MoM;
    int32_t MoMdepth,notarized_height,height,txi;
};

struct safecoin_ccdata_entry { uint256 MoM; int32_t notarized_height,safeheight,txi; char symbol[65]; };
struct safecoin_ccdatapair { int32_t notarized_height,MoMoMoffset; };

struct safecoin_ccdataMoMoM
{
    uint256 MoMoM;
    int32_t safestarti,safeendi,MoMoMoffset,MoMoMdepth,numpairs,len;
    struct safecoin_ccdatapair *pairs;
};

struct safecoin_ccdata
{
    struct safecoin_ccdata *next,*prev;
    struct safecoin_ccdataMoM MoMdata;
    uint32_t CCid,len;
    char symbol[65];
};

struct safecoin_state
{
    uint256 NOTARIZED_HASH,NOTARIZED_DESTTXID,MoM;
    int32_t SAVEDHEIGHT,CURRENT_HEIGHT,NOTARIZED_HEIGHT,MoMdepth;
    uint32_t SAVEDTIMESTAMP;
    uint64_t deposited,issued,withdrawn,approved,redeemed,shorted;
    struct notarized_checkpoint *NPOINTS; int32_t NUM_NPOINTS,last_NPOINTSi;
    struct safecoin_event **Safecoin_events; int32_t Safecoin_numevents;
    uint32_t RTbufs[64][3]; uint64_t RTmask;
};

#endif /* SAFECOIN_STRUCTS_H */
