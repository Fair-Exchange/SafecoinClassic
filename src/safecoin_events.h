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

#ifndef H_SAFECOINEVENTS_H
#define H_SAFECOINEVENTS_H
#include "safecoin_defs.h"

struct safecoin_event *safecoin_eventadd(struct safecoin_state *sp,int32_t height,char *symbol,uint8_t type,uint8_t *data,uint16_t datalen)
{
    struct safecoin_event *ep=0; uint16_t len = (uint16_t)(sizeof(*ep) + datalen);
    if ( sp != nullptr && ASSETCHAINS_SYMBOL[0] != '\0' )
    {
        portable_mutex_lock(&safecoin_mutex);
        ep = (struct safecoin_event *)calloc(1,len);
        ep->len = len;
        ep->height = height;
        ep->type = type;
        strcpy(ep->symbol,symbol);
        if ( datalen != 0 )
            memcpy(ep->space,data,datalen);
        sp->Safecoin_events = (struct safecoin_event **)realloc(sp->Safecoin_events,(1 + sp->Safecoin_numevents) * sizeof(*sp->Safecoin_events));
        sp->Safecoin_events[sp->Safecoin_numevents++] = ep;
        portable_mutex_unlock(&safecoin_mutex);
    }
    return ep;
}

void safecoin_eventadd_notarized(struct safecoin_state *sp,char *symbol,int32_t height,char *dest,uint256 notarized_hash,uint256 notarized_desttxid,int32_t notarizedheight,uint256 MoM,int32_t MoMdepth)
{
    static uint32_t counter; int8_t verified=0; char *coin; struct safecoin_event_notarized N;
    coin = ASSETCHAINS_SYMBOL[0] == '\0' ? (char *)"SAFE" : ASSETCHAINS_SYMBOL;
    if ( IS_SAFECOIN_NOTARY && (verified= safecoin_verifynotarization(symbol,dest,height,notarizedheight,notarized_hash,notarized_desttxid)) < 0 )
    {
        if ( counter++ < 100 )
            printf("[%s] error validating notarization ht.%d notarized_height.%d, if on a pruned %s node this can be ignored\n",ASSETCHAINS_SYMBOL,height,notarizedheight,dest);
    }
    else if ( strcmp(symbol,coin) == 0 )
    {
        if ( 0 && IS_SAFECOIN_NOTARY && verified != 0 )
            fprintf(stderr,"validated [%s] ht.%d notarized %d\n",coin,height,notarizedheight);
        memset(&N,0,sizeof(N));
        N.blockhash = notarized_hash;
        N.desttxid = notarized_desttxid;
        N.notarizedheight = notarizedheight;
        N.MoM = MoM;
        N.MoMdepth = MoMdepth;
        strncpy(N.dest,dest,sizeof(N.dest)-1);
        safecoin_eventadd(sp,height,symbol,SAFECOIN_EVENT_NOTARIZED,(uint8_t *)&N,sizeof(N));
        if ( sp != nullptr )
            safecoin_notarized_update(sp,height,notarizedheight,notarized_hash,notarized_desttxid,MoM,MoMdepth);
    }
}

void safecoin_eventadd_pubkeys(struct safecoin_state *sp,char *symbol,int32_t height,uint8_t num,uint8_t pubkeys[64][33])
{
    struct safecoin_event_pubkeys P;
    //printf("eventadd pubkeys ht.%d\n",height);
    memset(&P,0,sizeof(P));
    P.num = num;
    memcpy(P.pubkeys,pubkeys,33 * num);
    safecoin_eventadd(sp,height,symbol,SAFECOIN_EVENT_RATIFY,(uint8_t *)&P,(int32_t)(sizeof(P.num) + 33 * num));
    if ( sp != nullptr )
        safecoin_notarysinit(height,pubkeys,num);
}

void safecoin_eventadd_pricefeed(struct safecoin_state *sp,char *symbol,int32_t height,uint32_t *prices,uint8_t num)
{
    struct safecoin_event_pricefeed F;
    if ( num == sizeof(F.prices)/sizeof(*F.prices) )
    {
        memset(&F,0,sizeof(F));
        F.num = num;
        memcpy(F.prices,prices,sizeof(*F.prices) * num);
        safecoin_eventadd(sp,height,symbol,SAFECOIN_EVENT_PRICEFEED,(uint8_t *)&F,(int32_t)(sizeof(F.num) + sizeof(*F.prices) * num));
        if ( sp != nullptr )
            safecoin_pvals(height,prices,num);
    } //else fprintf(stderr,"skip pricefeed[%d]\n",num);
}

void safecoin_eventadd_opreturn(struct safecoin_state *sp,char *symbol,int32_t height,uint256 txid,uint64_t value,uint16_t vout,uint8_t *buf,uint16_t opretlen)
{
    struct safecoin_event_opreturn O; uint8_t *opret;
    if ( ASSETCHAINS_SYMBOL[0] != '\0' )
    {
        opret = (uint8_t *)calloc(1,sizeof(O) + opretlen + 16);
        O.txid = txid;
        O.value = value;
        O.vout = vout;
        memcpy(opret,&O,sizeof(O));
        memcpy(&opret[sizeof(O)],buf,opretlen);
        O.oplen = (int32_t)(opretlen + sizeof(O));
        safecoin_eventadd(sp,height,symbol,SAFECOIN_EVENT_OPRETURN,opret,O.oplen);
        free(opret);
        if ( sp != nullptr )
            safecoin_opreturn(height,value,buf,opretlen,txid,vout,symbol);
    }
}

void safecoin_event_undo(struct safecoin_state *sp,struct safecoin_event *ep)
{
    switch ( ep->type )
    {
        case SAFECOIN_EVENT_RATIFY: printf("rewind of ratify, needs to be coded.%d\n",ep->height); break;
        case SAFECOIN_EVENT_NOTARIZED: break;
        case SAFECOIN_EVENT_SAFEHEIGHT:
            if ( ep->height <= sp->SAVEDHEIGHT )
                sp->SAVEDHEIGHT = ep->height;
            break;
        case SAFECOIN_EVENT_PRICEFEED:
            // backtrack prices;
            break;
        case SAFECOIN_EVENT_OPRETURN:
            // backtrack opreturns
            break;
    }
}

void safecoin_event_rewind(struct safecoin_state *sp,char *symbol,int32_t height)
{
    struct safecoin_event *ep;
    if ( sp != nullptr )
    {
        if ( ASSETCHAINS_SYMBOL[0] == '\0' && height <= SAFECOIN_LASTMINED && prevSAFECOIN_LASTMINED != 0 )
        {
            printf("undo SAFECOIN_LASTMINED %d <- %d\n",SAFECOIN_LASTMINED,prevSAFECOIN_LASTMINED);
            SAFECOIN_LASTMINED = prevSAFECOIN_LASTMINED;
            prevSAFECOIN_LASTMINED = 0;
        }
        while ( sp->Safecoin_events != nullptr && sp->Safecoin_numevents > 0 )
        {
            if ( (ep= sp->Safecoin_events[sp->Safecoin_numevents-1]) != nullptr )
            {
                if ( ep->height < height )
                    break;
                //printf("[%s] undo %s event.%c ht.%d for rewind.%d\n",ASSETCHAINS_SYMBOL,symbol,ep->type,ep->height,height);
                safecoin_event_undo(sp,ep);
                sp->Safecoin_numevents--;
            }
        }
    }
}

void safecoin_setsafeheight(struct safecoin_state *sp,int32_t safeheight,uint32_t timestamp)
{
    if ( sp != nullptr )
    {
        if ( safeheight > sp->SAVEDHEIGHT )
        {
            sp->SAVEDHEIGHT = safeheight;
            sp->SAVEDTIMESTAMP = timestamp;
        }
        if ( safeheight > sp->CURRENT_HEIGHT )
            sp->CURRENT_HEIGHT = safeheight;
    }
}

void safecoin_eventadd_safeheight(struct safecoin_state *sp,char *symbol,int32_t height,int32_t safeheight,uint32_t timestamp)
{
    uint32_t buf[2];
    if ( safeheight > 0 )
    {
        buf[0] = (uint32_t)safeheight;
        buf[1] = timestamp;
        safecoin_eventadd(sp,height,symbol,SAFECOIN_EVENT_SAFEHEIGHT,(uint8_t *)buf,sizeof(buf));
        if ( sp != nullptr )
            safecoin_setsafeheight(sp,safeheight,timestamp);
    }
    else
    {
        //fprintf(stderr,"REWIND safeheight.%d\n",safeheight);
        safeheight = -safeheight;
        safecoin_eventadd(sp,height,symbol,SAFECOIN_EVENT_REWIND,(uint8_t *)&height,sizeof(height));
        if ( sp != nullptr )
            safecoin_event_rewind(sp,symbol,height);
    }
}


/*void safecoin_eventadd_deposit(int32_t actionflag,char *symbol,int32_t height,uint64_t safecoinshis,char *fiat,uint64_t fiatoshis,uint8_t rmd160[20],bits256 safetxid,uint16_t safevout,uint64_t price)
 {
 uint8_t opret[512]; uint16_t opretlen;
 safecoin_eventadd_opreturn(symbol,height,SAFECOIN_OPRETURN_DEPOSIT,safetxid,safecoinshis,safevout,opret,opretlen);
 }

 void safecoin_eventadd_issued(int32_t actionflag,char *symbol,int32_t height,int32_t fiatheight,bits256 fiattxid,uint16_t fiatvout,bits256 safetxid,uint16_t safevout,uint64_t fiatoshis)
 {
 uint8_t opret[512]; uint16_t opretlen;
 safecoin_eventadd_opreturn(symbol,height,SAFECOIN_OPRETURN_ISSUED,fiattxid,fiatoshis,fiatvout,opret,opretlen);
 }

 void safecoin_eventadd_withdraw(int32_t actionflag,char *symbol,int32_t height,uint64_t safecoinshis,char *fiat,uint64_t fiatoshis,uint8_t rmd160[20],bits256 fiattxid,int32_t fiatvout,uint64_t price)
 {
 uint8_t opret[512]; uint16_t opretlen;
 safecoin_eventadd_opreturn(symbol,height,SAFECOIN_OPRETURN_WITHDRAW,fiattxid,fiatoshis,fiatvout,opret,opretlen);
 }

 void safecoin_eventadd_redeemed(int32_t actionflag,char *symbol,int32_t height,bits256 safetxid,uint16_t safevout,int32_t fiatheight,bits256 fiattxid,uint16_t fiatvout,uint64_t safecoinshis)
 {
 uint8_t opret[512]; uint16_t opretlen;
 safecoin_eventadd_opreturn(symbol,height,SAFECOIN_OPRETURN_REDEEMED,safetxid,safecoinshis,safevout,opret,opretlen);
 }*/

// process events
//

#endif
