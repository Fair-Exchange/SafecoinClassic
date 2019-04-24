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

// paxdeposit equivalent in reverse makes opreturn and SAFE does the same in reverse
#include "safecoin_defs.h"

int8_t pax_fiatstatus(uint64_t *available,uint64_t *deposited,uint64_t *issued,uint64_t *withdrawn,uint64_t *approved,uint64_t *redeemed,char *base)
{
    int32_t baseid; struct safecoin_state *sp; int64_t netliability,maxallowed,maxval;
    *available = *deposited = *issued = *withdrawn = *approved = *redeemed = 0;
    if ( (baseid= safecoin_baseid(base)) != -1 )
    {
        if ( (sp= safecoin_stateptrget(base)) != nullptr )
        {
            *deposited = sp->deposited;
            *issued = sp->issued;
            *withdrawn = sp->withdrawn;
            *approved = sp->approved;
            *redeemed = sp->redeemed;
            maxval = sp->approved;
            if ( sp->withdrawn > maxval )
                maxval = sp->withdrawn;
            netliability = (sp->issued - maxval) - sp->shorted;
            maxallowed = safecoin_maxallowed(baseid);
            if ( netliability < maxallowed )
                *available = (maxallowed - netliability);
            //printf("%llu - %llu %s %.8f %.8f %.8f %.8f %.8f\n",(long long)maxallowed,(long long)netliability,base,dstr(*deposited),dstr(*issued),dstr(*withdrawn),dstr(*approved),dstr(*redeemed));
            return 0;
        } else printf("pax_fiatstatus cant get basesp.%s\n",base);
    } // else printf("pax_fiatstatus illegal base.%s\n",base);
    return -1;
}

void pax_keyset(uint8_t *buf,uint256 txid,uint16_t vout,uint8_t type)
{
    memcpy(buf,&txid,32);
    memcpy(&buf[32],&vout,2);
    buf[34] = type;
}

struct pax_transaction *safecoin_paxfind(uint256 txid,uint16_t vout,uint8_t type)
{
    struct pax_transaction *pax; uint8_t buf[35];
    pthread_mutex_lock(&safecoin_mutex);
    pax_keyset(buf,txid,vout,type);
    HASH_FIND(hh,PAX,buf,sizeof(buf),pax);
    pthread_mutex_unlock(&safecoin_mutex);
    return pax;
}

struct pax_transaction *safecoin_paxfinds(uint256 txid,uint16_t vout)
{
    struct pax_transaction *pax; int32_t i; uint8_t types[] = { 'I', 'D', 'X', 'A', 'W' };
    for (i=0; i<sizeof(types)/sizeof(*types); i++)
        if ( (pax= safecoin_paxfind(txid,vout,types[i])) != nullptr )
            return pax;
    return nullptr;
}

struct pax_transaction *safecoin_paxmark(int32_t height,uint256 txid,uint16_t vout,uint8_t type,int32_t mark)
{
    struct pax_transaction *pax; uint8_t buf[35];
    pthread_mutex_lock(&safecoin_mutex);
    pax_keyset(buf,txid,vout,type);
    HASH_FIND(hh,PAX,buf,sizeof(buf),pax);
    if ( pax == nullptr )
    {
        pax = (struct pax_transaction *)calloc(1,sizeof(*pax));
        pax->txid = txid;
        pax->vout = vout;
        pax->type = type;
        memcpy(pax->buf,buf,sizeof(pax->buf));
        HASH_ADD_KEYPTR(hh,PAX,pax->buf,sizeof(pax->buf),pax);
        //printf("ht.%d create pax.%p mark.%d\n",height,pax,mark);
    }
    else
    {
        pax->marked = mark;
        //if ( height > 214700 || pax->height > 214700 )
        //    printf("mark ht.%d %.8f %.8f\n",pax->height,dstr(pax->safecoinshis),dstr(pax->fiatoshis));
    }
    pthread_mutex_unlock(&safecoin_mutex);
    return pax;
}

void safecoin_paxdelete(struct pax_transaction *pax)
{
    return; // breaks when out of order
    pthread_mutex_lock(&safecoin_mutex);
    HASH_DELETE(hh,PAX,pax);
    pthread_mutex_unlock(&safecoin_mutex);
}

void safecoin_gateway_deposit(char *coinaddr,uint64_t value,char *symbol,uint64_t fiatoshis,uint8_t *rmd160,uint256 txid,uint16_t vout,uint8_t type,int32_t height,int32_t otherheight,char *source,int32_t approved) // assetchain context
{
    struct pax_transaction *pax; uint8_t buf[35]; int32_t addflag = 0; struct safecoin_state *sp; char str[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN],*s;
    //if ( SAFECOIN_PAX == 0 )
    //    return;
    //if ( strcmp(symbol,ASSETCHAINS_SYMBOL) != 0 )
    //    return;
    sp = safecoin_stateptr(str,dest);
    pthread_mutex_lock(&safecoin_mutex);
    pax_keyset(buf,txid,vout,type);
    HASH_FIND(hh,PAX,buf,sizeof(buf),pax);
    if ( pax == nullptr )
    {
        pax = (struct pax_transaction *)calloc(1,sizeof(*pax));
        pax->txid = txid;
        pax->vout = vout;
        pax->type = type;
        memcpy(pax->buf,buf,sizeof(pax->buf));
        HASH_ADD_KEYPTR(hh,PAX,pax->buf,sizeof(pax->buf),pax);
        addflag = 1;
        if ( 0 && ASSETCHAINS_SYMBOL[0] == '\0' )
        {
            int32_t i; for (i=0; i<32; i++)
                printf("%02x",((uint8_t *)&txid)[i]);
            printf(" v.%d [%s] kht.%d ht.%d create pax.%p symbol.%s source.%s\n",vout,ASSETCHAINS_SYMBOL,height,otherheight,pax,symbol,source);
        }
    }
    pthread_mutex_unlock(&safecoin_mutex);
    if ( coinaddr != nullptr )
    {
        strcpy(pax->coinaddr,coinaddr);
        if ( value != 0 )
            pax->safecoinshis = value;
        if ( symbol != nullptr )
            strcpy(pax->symbol,symbol);
        if ( source != nullptr )
            strcpy(pax->source,source);
        if ( fiatoshis != 0 )
            pax->fiatoshis = fiatoshis;
        if ( rmd160 != nullptr )
            memcpy(pax->rmd160,rmd160,20);
        if ( height != 0 )
            pax->height = height;
        if ( otherheight != 0 )
            pax->otherheight = otherheight;
    }
    else
    {
        pax->marked = height;
        //printf("pax.%p MARK DEPOSIT ht.%d other.%d\n",pax,height,otherheight);
    }
}

int32_t safecoin_rwapproval(int32_t rwflag,uint8_t *opretbuf,struct pax_transaction *pax)
{
    int32_t i,len = 0;
    if ( rwflag == 1 )
    {
        for (i=0; i<32; i++)
            opretbuf[len++] = ((uint8_t *)&pax->txid)[i];
        opretbuf[len++] = pax->vout & 0xff;
        opretbuf[len++] = (pax->vout >> 8) & 0xff;
    }
    else
    {
        for (i=0; i<32; i++)
            ((uint8_t *)&pax->txid)[i] = opretbuf[len++];
        //for (i=0; i<32; i++)
        //    printf("%02x",((uint8_t *)&pax->txid)[31-i]);
        pax->vout = opretbuf[len++];
        pax->vout += ((uint32_t)opretbuf[len++] << 8);
        //printf(" txid v.%d\n",pax->vout);
    }
    len += iguana_rwnum(rwflag,&opretbuf[len],sizeof(pax->safecoinshis),&pax->safecoinshis);
    len += iguana_rwnum(rwflag,&opretbuf[len],sizeof(pax->fiatoshis),&pax->fiatoshis);
    len += iguana_rwnum(rwflag,&opretbuf[len],sizeof(pax->height),&pax->height);
    len += iguana_rwnum(rwflag,&opretbuf[len],sizeof(pax->otherheight),&pax->otherheight);
    if ( rwflag != 0 )
    {
        memcpy(&opretbuf[len],pax->rmd160,20), len += 20;
        for (i=0; i<4; i++)
            opretbuf[len++] = pax->source[i];
    }
    else
    {
        memcpy(pax->rmd160,&opretbuf[len],20), len += 20;
        for (i=0; i<4; i++)
            pax->source[i] = opretbuf[len++];
    }
    return len;
}

int32_t safecoin_issued_opreturn(char *base,uint256 *txids,uint16_t *vouts,int64_t *values,int64_t *srcvalues,int32_t *safeheights,int32_t *otherheights,int8_t *baseids,uint8_t *rmd160s,uint8_t *opretbuf,int32_t opretlen,bool issafecoin)
{
    struct pax_transaction p,*pax; int32_t i,n=0,j,len=0,incr,height,otherheight; uint8_t type,rmd160[20]; uint64_t fiatoshis; char symbol[SAFECOIN_ASSETCHAIN_MAXLEN];
    //if ( SAFECOIN_PAX == 0 )
    //    return(0);
    incr = 34;
    if (issafecoin)
        incr += 2*sizeof(fiatoshis) + 2*sizeof(height) + 20 + 4;
    //41e77b91cb68dc2aa02fa88550eae6b6d44db676a7e935337b6d1392d9718f03cb0200305c90660400000000fbcbeb1f000000bde801006201000058e7945ad08ddba1eac9c9b6c8e1e97e8016a2d152

    // 41e94d736ec69d88c08b5d238abeeca609c02357a8317e0d56c328bcb1c259be5d0200485bc80200000000404b4c000000000059470200b80b000061f22ba7d19fe29ac3baebd839af8b7127d1f9075553440046bb4cc7a3b5cd39dffe7206507a3482a00780e617f68b273cce9817ed69298d02001069ca1b0000000080f0fa02000000005b470200b90b000061f22ba7d19fe29ac3baebd839af8b7127d1f90755

    //for (i=0; i<opretlen; i++)
    //    printf("%02x",opretbuf[i]);
    //printf(" opretlen.%d (%s)\n",opretlen,base);
    //printf(" opretlen.%d vs %d incr.%d (%d)\n",opretlen,(int32_t)(2*sizeof(fiatoshis) + 2*sizeof(height) + 20 + 2),incr,opretlen/incr);
    //if ( ASSETCHAINS_SYMBOL[0] == '\0' || strncmp(ASSETCHAINS_SYMBOL,base,strlen(base)) == 0 )
    {
        type = opretbuf[0];
        opretbuf++, opretlen--;
        for (n=0; n<opretlen/incr; n++)
        {
            if ( issafecoin )
            {
                memset(&p,0,sizeof(p));
                len += safecoin_rwapproval(0,&opretbuf[len],&p);
                if ( values != nullptr && srcvalues != nullptr && safeheights != nullptr && otherheights != nullptr && baseids != nullptr && rmd160s != nullptr )
                {
                    txids[n] = p.txid;
                    vouts[n] = p.vout;
                    values[n] = (strcmp("SAFE",base) == 0) ? p.safecoinshis : p.fiatoshis;
                    srcvalues[n] = (strcmp("SAFE",base) == 0) ? p.fiatoshis : p.safecoinshis;
                    safeheights[n] = p.height;
                    otherheights[n] = p.otherheight;
                    memcpy(&rmd160s[n * 20],p.rmd160,20);
                    baseids[n] = safecoin_baseid(p.source);
                    // if ( 0 )
                    // {
                    //     char coinaddr[64];
                    //     bitcoin_address(coinaddr,60,&rmd160s[n * 20],20);
                    //     printf(">>>>>>> %s: (%s) fiat %.8f safeheight.%d other.%d -> %s %.8f\n",type=='A'?"approvedA":"issuedX",baseids[n]>=0?CURRENCIES[baseids[n]]:"???",dstr(p.fiatoshis),safeheights[n],otherheights[n],coinaddr,dstr(values[n]));
                    // }
                }
            }
            else
            {
                for (i=0; i<4; i++)
                    base[i] = opretbuf[opretlen-4+i];
                for (j=0; j<32; j++)
                {
                    ((uint8_t *)&txids[n])[j] = opretbuf[len++];
                    //printf("%02x",((uint8_t *)&txids[n])[j]);
                }
                vouts[n] = opretbuf[len++];
                vouts[n] = (opretbuf[len++] << 8) | vouts[n];
                baseids[n] = safecoin_baseid(base);
                if ( (pax= safecoin_paxfinds(txids[n],vouts[n])) != nullptr )
                {
                    values[n] = (strcmp("SAFE",base) == 0) ? pax->safecoinshis : pax->fiatoshis;
                    srcvalues[n] = (strcmp("SAFE",base) == 0) ? pax->fiatoshis : pax->safecoinshis;
                    safeheights[n] = pax->height;
                    otherheights[n] = pax->otherheight;
                    memcpy(&rmd160s[n * 20],pax->rmd160,20);
                }
            }
            //printf(" safecoin_issued_opreturn issuedtxid v%d i.%d opretlen.%d\n",vouts[n],n,opretlen);
        }
    }
    return n;
}

int8_t safecoin_paxcmp(char *symbol,int32_t safeheight,uint64_t value,uint64_t checkvalue,uint64_t seed)
{
    int32_t ratio;
    if (checkvalue != 0) {
        if ( seed == 0 )
        {
            ratio = (value << 6) / checkvalue;
            if ( ratio >= 60 && ratio <= 67 )
                return 0;
            if ( ASSETCHAINS_SYMBOL[0] != '\0' )
                printf("ht.%d ignore mismatched %s value %lld vs checkvalue %lld -> ratio.%d\n",safeheight,symbol,(long long)value,(long long)checkvalue,ratio);
            return -1;
        }
        ratio = (value << 10) / checkvalue;
        if ( ratio == 1024 )
            return 0;
    }
    return value != checkvalue;
}

uint64_t safecoin_paxtotal()
{
    struct pax_transaction *pax,*pax2,*tmp,*tmp2; char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN],*str; int32_t i,ht; int64_t checktoshis; uint64_t seed,total = 0; struct safecoin_state *basesp;
    if ( !SAFECOIN_PASSPORT_INITDONE ) //SAFECOIN_PAX == 0 ||
        return 0;
    if ( !safecoin_isrealtime(&ht) )
        return 0;
    HASH_ITER(hh,PAX,pax,tmp)
    {
        if ( pax->marked != 0 )
            continue;
        str = pax->type == 'A' || pax->type == 'D' || pax->type == 'X' ? pax->symbol : pax->source;
        basesp = safecoin_stateptrget(str);
        if ( basesp != nullptr && !pax->didstats )
        {
            if ( pax->type == 'I' && (pax2= safecoin_paxfind(pax->txid,pax->vout,'D')) != nullptr )
            {
                if ( pax2->fiatoshis != 0 )
                {
                    pax->safecoinshis = pax2->safecoinshis;
                    pax->fiatoshis = pax2->fiatoshis;
                    basesp->issued += pax->fiatoshis;
                    pax->didstats = true;
                    if ( strcmp(str,ASSETCHAINS_SYMBOL) == 0 )
                        printf("########### %p issued %s += %.8f safeheight.%d %.8f other.%d\n",basesp,str,dstr(pax->fiatoshis),pax->height,dstr(pax->safecoinshis),pax->otherheight);
                    pax2->marked = pax->height;
                    pax->marked = pax->height;
                }
            }
            else if ( pax->type == 'W' )
            {
                //bitcoin_address(coinaddr,addrtype,rmd160,20);
                if ( (checktoshis= safecoin_paxprice(&seed,pax->height,pax->source,(char *)"SAFE",(uint64_t)pax->fiatoshis)) != 0 )
                {
                    if ( safecoin_paxcmp(pax->source,pax->height,pax->safecoinshis,checktoshis,seed) != 0 )
                    {
                        pax->marked = pax->height;
                        //printf("WITHDRAW.%s mark <- %d %.8f != %.8f\n",pax->source,pax->height,dstr(checktoshis),dstr(pax->safecoinshis));
                    }
                    else if ( pax->validated == 0 )
                    {
                        pax->validated = pax->safecoinshis = checktoshis;
                        //int32_t j; for (j=0; j<32; j++)
                        //    printf("%02x",((uint8_t *)&pax->txid)[j]);
                        //if ( strcmp(str,ASSETCHAINS_SYMBOL) == 0 )
                        //    printf(" v%d %p got WITHDRAW.%s safe.%d ht.%d %.8f -> %.8f/%.8f\n",pax->vout,pax,pax->source,pax->height,pax->otherheight,dstr(pax->fiatoshis),dstr(pax->safecoinshis),dstr(checktoshis));
                    }
                }
            }
        }
    }
    safecoin_stateptr(symbol,dest);
    HASH_ITER(hh,PAX,pax,tmp)
    {
        pax->ready = false;
        if ( 0 && pax->type == 'A' )
            printf("%p pax.%s <- %s marked.%d %.8f -> %.8f validated.%d approved.%d\n",pax,pax->symbol,pax->source,pax->marked,dstr(pax->safecoinshis),dstr(pax->fiatoshis),pax->validated != 0,pax->approved != 0);
        if ( pax->marked != 0 )
            continue;
        if ( strcmp(symbol,pax->symbol) == 0 || pax->type == 'A' )
        {
            if ( pax->marked == 0 )
            {
                if ( safecoin_is_issuer() )
                {
                    if ( pax->validated != 0 && pax->type == 'D' )
                    {
                        total += pax->fiatoshis;
                        pax->ready = true;
                    }
                }
                else if ( pax->approved != 0 && pax->type == 'A' )
                {
                    if ( pax->validated != 0 )
                    {
                        total += pax->safecoinshis;
                        pax->ready = true;
                    }
                    else
                    {
                        seed = 0;
                        checktoshis = safecoin_paxprice(&seed,pax->height,pax->source,(char *)"SAFE",(uint64_t)pax->fiatoshis);
                        //printf("paxtotal PAX_fiatdest ht.%d price %s %.8f -> SAFE %.8f vs %.8f\n",pax->height,pax->symbol,(double)pax->fiatoshis/COIN,(double)pax->safecoinshis/COIN,(double)checktoshis/COIN);
                        //printf(" v%d %.8f k.%d ht.%d\n",pax->vout,dstr(pax->safecoinshis),pax->height,pax->otherheight);
                        if ( seed != 0 && checktoshis != 0 )
                        {
                            if ( checktoshis == pax->safecoinshis )
                            {
                                total += pax->safecoinshis;
                                pax->validated = pax->safecoinshis;
                                pax->ready = true;
                            } else pax->marked = pax->height;
                        }
                    }
                }
                if ( 0 && pax->ready )
                    printf("%p (%c) pax.%s marked.%d %.8f -> %.8f validated.%d approved.%d ready.%d ht.%d\n",pax,pax->type,pax->symbol,pax->marked,dstr(pax->safecoinshis),dstr(pax->fiatoshis),pax->validated != 0,pax->approved != 0,pax->ready,pax->height);
            }
        }
    }
    //printf("paxtotal %.8f\n",dstr(total));
    return total;
}

static int _paxorder(const void *a,const void *b)
{
#define pax_a (*(struct pax_transaction **)a)
#define pax_b (*(struct pax_transaction **)b)
    uint64_t aval,bval;
    aval = pax_a->fiatoshis + pax_a->safecoinshis + pax_a->height;
    bval = pax_b->fiatoshis + pax_b->safecoinshis + pax_b->height;
	if ( bval > aval )
		return -1;
	else if ( bval < aval )
		return 1;
	return 0;
#undef pax_a
#undef pax_b
}

int32_t safecoin_pending_withdraws(char *opretstr) // todo: enforce deterministic order
{
    struct pax_transaction *pax,*pax2,*tmp,*paxes[64]; uint8_t opretbuf[16384*4]; int32_t i,n,ht,len=0; uint64_t total = 0;
    if ( SAFECOIN_PAX == 0 || !SAFECOIN_PASSPORT_INITDONE )
        return 0;
    if ( !safecoin_isrealtime(&ht) || ASSETCHAINS_SYMBOL[0] != '\0' )
        return 0;
    n = 0;
    HASH_ITER(hh,PAX,pax,tmp)
    {
        if ( pax->type == 'W' )
        {
            if ( (pax2= safecoin_paxfind(pax->txid,pax->vout,'A')) != 0 )
                if ( pax2->approved != 0 )
                    pax->approved = pax2->approved;
            else if ( (pax2= safecoin_paxfind(pax->txid,pax->vout,'X')) != 0 )
                pax->approved = pax->height;
            //printf("pending_withdraw: pax %s marked.%u approved.%u validated.%llu\n",pax->symbol,pax->marked,pax->approved,(long long)pax->validated);
            if ( pax->marked == 0 && pax->approved == 0 && pax->validated != 0 ) //strcmp((char *)"SAFE",pax->symbol) == 0 &&
            {
                if ( n < sizeof(paxes)/sizeof(*paxes) )
                {
                    paxes[n++] = pax;
                    //int32_t j; for (j=0; j<32; j++)
                    //    printf("%02x",((uint8_t *)&pax->txid)[j]);
                    //printf(" %s.(safeht.%d ht.%d marked.%u approved.%d validated %.8f) %.8f\n",pax->source,pax->height,pax->otherheight,pax->marked,pax->approved,dstr(pax->validated),dstr(pax->safecoinshis));
                }
            }
        }
    }
    opretstr[0] = '\0';
    if ( n > 0 )
    {
        opretbuf[len++] = 'A';
        qsort(paxes,n,sizeof(*paxes),_paxorder);
        for (i=0; i<n; i++)
            if ( len < (sizeof(opretbuf)>>3)*7 )
                len += safecoin_rwapproval(1,&opretbuf[len],paxes[i]);
        if ( len > 0 )
            init_hexbytes_noT(opretstr,opretbuf,len);
    }
    //fprintf(stderr,"safecoin_pending_withdraws len.%d PAXTOTAL %.8f\n",len,dstr(safecoin_paxtotal()));
    return len;
}

bool safecoin_gateway_deposits(CMutableTransaction *txNew,char *base,bool tosafecoin)
{
    struct pax_transaction *pax,*tmp; char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; uint8_t *script,opcode,opret[16384*4],data[16384*4]; int32_t i,ht,len=0,opretlen=0,numvouts=1; struct safecoin_state *sp; uint64_t available,deposited,issued,withdrawn,approved,redeemed,mask,sum = 0; int8_t baseid;
    if ( !SAFECOIN_PASSPORT_INITDONE )//SAFECOIN_PAX == 0 ||
        return false;
    struct safecoin_state *safesp = safecoin_stateptrget((char *)"SAFE");
    sp = safecoin_stateptr(symbol,dest);
    strcpy(symbol,base);
    if ( ASSETCHAINS_SYMBOL[0] != '\0' && safecoin_baseid(ASSETCHAINS_SYMBOL) == -1 )
        return false;
    PENDING_SAFECOIN_TX = 0;
    for (i=0; i<3; i++)
    {
        if ( safecoin_isrealtime(&ht) )
            break;
        sleep(1);
    }
    if ( i == 3 )
    {
        if ( !tosafecoin )
            printf("%s not realtime ht.%d\n",ASSETCHAINS_SYMBOL,ht);
        return false;
    }
    if ( !tosafecoin )
    {
        opcode = 'I';
    }
    else
    {
        opcode = 'X';
        if ( 1 || safecoin_paxtotal() == 0 )
            return false;
    }
    HASH_ITER(hh,PAX,pax,tmp)
    {
        if ( pax->type != 'D' && pax->type != 'A' )
            continue;
        {
#ifdef SAFECOIN_ASSETCHAINS_WAITNOTARIZE
            if ( pax->height > 236000 )
            {
                if ( safesp != nullptr && safesp->NOTARIZED_HEIGHT >= pax->height )
                    pax->validated = pax->safecoinshis;
                else if ( safesp->CURRENT_HEIGHT > pax->height+30 )
                    pax->validated = pax->ready = false;
            }
            else
            {
                if ( safesp != nullptr && (safesp->NOTARIZED_HEIGHT >= pax->height || safesp->CURRENT_HEIGHT > pax->height+30) ) // assumes same chain as notarize
                    pax->validated = pax->safecoinshis;
                else pax->validated = pax->ready = false;
            }
#else
            pax->validated = pax->safecoinshis;
#endif
        }
        if ( ASSETCHAINS_SYMBOL[0] != '\0' && (pax_fiatstatus(&available,&deposited,&issued,&withdrawn,&approved,&redeemed,symbol) != 0 || available < pax->fiatoshis) )
        {
            //if ( pax->height > 214700 || strcmp(ASSETCHAINS_SYMBOL,symbol) == 0 )
            //    printf("miner.[%s]: skip %s %.8f when avail %.8f deposited %.8f, issued %.8f withdrawn %.8f approved %.8f redeemed %.8f\n",ASSETCHAINS_SYMBOL,symbol,dstr(pax->fiatoshis),dstr(available),dstr(deposited),dstr(issued),dstr(withdrawn),dstr(approved),dstr(redeemed));
            continue;
        }
        /*printf("pax.%s marked.%d %.8f -> %.8f ready.%d validated.%d\n",pax->symbol,pax->marked,dstr(pax->safecoinshis),dstr(pax->fiatoshis),pax->ready!=0,pax->validated!=0);
        if ( pax->marked != 0 || (pax->type != 'D' && pax->type != 'A') || pax->ready == 0 )
        {
            printf("reject 2\n");
            continue;
        }*/
        if ( ASSETCHAINS_SYMBOL[0] != '\0' && (strcmp(pax->symbol,symbol) != 0 || pax->validated == 0 || !pax->ready) )
        {
            if ( strcmp(pax->symbol,ASSETCHAINS_SYMBOL) == 0 )
                printf("pax->symbol.%s != %s or null pax->validated %.8f ready.%d ht.(%d %d)\n",pax->symbol,symbol,dstr(pax->validated),pax->ready,safesp->CURRENT_HEIGHT,pax->height);
            pax->marked = pax->height;
            continue;
        }
        if ( !pax->ready )
            continue;
        if ( pax->type == 'A' && ASSETCHAINS_SYMBOL[0] == '\0' )
        {
            if ( safesp != nullptr )
            {
                if ( (baseid= safecoin_baseid(pax->symbol)) == -1 || ((1LL << baseid) & sp->RTmask) == 0 )
                {
                    printf("not RT for (%s) %llx baseid.%d %llx\n",pax->symbol,(long long)sp->RTmask,baseid,(long long)(1LL<<baseid));
                    continue;
                }
            } else continue;
        }

        //printf("redeem.%d? (%c) %p pax.%s marked.%d %.8f -> %.8f ready.%d validated.%d approved.%d\n",tosafecoin,pax->type,pax,pax->symbol,pax->marked,dstr(pax->safecoinshis),dstr(pax->fiatoshis),pax->ready!=0,pax->validated!=0,pax->approved!=0);
        if ( 0 && ASSETCHAINS_SYMBOL[0] != '\0' )
            printf("pax.%s marked.%d %.8f -> %.8f\n",ASSETCHAINS_SYMBOL,pax->marked,dstr(pax->safecoinshis),dstr(pax->fiatoshis));
        if ( opcode == 'I' )
        {
            sum += pax->fiatoshis;
            if ( sum > available )
                break;
        }
        txNew->vout.resize(numvouts+1);
        txNew->vout[numvouts].nValue = (opcode == 'I') ? pax->fiatoshis : pax->safecoinshis;
        txNew->vout[numvouts].scriptPubKey.resize(25);
        script = (uint8_t *)&txNew->vout[numvouts].scriptPubKey[0];
        *script++ = 0x76;
        *script++ = 0xa9;
        *script++ = 20;
        memcpy(script,pax->rmd160,20), script += 20;
        *script++ = 0x88;
        *script++ = 0xac;
        if ( !tosafecoin )
        {
            for (i=0; i<32; i++)
                data[len++] = ((uint8_t *)&pax->txid)[i];
            data[len++] = pax->vout & 0xff;
            data[len++] = (pax->vout >> 8) & 0xff;
            PENDING_SAFECOIN_TX += pax->fiatoshis;
        }
        else
        {
            len += safecoin_rwapproval(1,&data[len],pax);
            PENDING_SAFECOIN_TX += pax->safecoinshis;
            printf(" len.%d vout.%u DEPOSIT %.8f <- pax.%s pending ht %d %d %.8f | ",len,pax->vout,(double)txNew->vout[numvouts].nValue/COIN,symbol,pax->height,pax->otherheight,dstr(PENDING_SAFECOIN_TX));
        }
        if ( numvouts++ >= 64 || sum > COIN )
            break;
    }
    if ( numvouts > 1 )
    {
        if ( tosafecoin )
            strcpy(symbol,(char *)"SAFE");
        for (i=0; symbol[i]!=0; i++)
            data[len++] = symbol[i];
        data[len++] = 0;
        for (i=0; i<len; i++)
            printf("%02x",data[i]);
        printf(" <- data[%d]\n",len);
        opretlen = safecoin_opreturnscript(opret,opcode,data,len);
        txNew->vout.resize(numvouts+1);
        txNew->vout[numvouts].nValue = 0;
        txNew->vout[numvouts].scriptPubKey.resize(opretlen);
        script = (uint8_t *)&txNew->vout[numvouts].scriptPubKey[0];
        memcpy(script,opret,opretlen);
        for (i=0; i<8; i++)
            printf("%02x",opret[i]);
        printf(" <- opret, MINER deposits.%d (%s) vouts.%d %.8f opretlen.%d\n",tosafecoin,ASSETCHAINS_SYMBOL,numvouts,dstr(PENDING_SAFECOIN_TX),opretlen);
        return true;
    }
    return false;
}

const char *banned_txids[] =
{
    "bcdf70f737f466d7d6331aac897dd02e74e5abf0ac2fb0cf846f7c9e3f015663", //////
    "75056885ca3be4fa65af4c54b98e1145010a2d635eb908f2bbad4d10e6a6d28e", //////
    "9030a5776795a6a595ed61433f9ebbb961faa8aaab9452a07d62425353ef5b7a", // #77197 Apr 7, 2018 2:26:15 PM
    "4d19f8f59e438001ee3840e98121f3c83dcfa369584739fad4bf3cf1d9d78747",
    "c1534cd8aeee8efa09a96f09fc60bf15f01fb18386443447602ae9dea5f293a0",
    "a199c5e9e4631e24f3f36b59bdabfd157c1d2b210ed5453c7b804a5b00539eb5",
    "c2d3c22acd51985e5446aa237c85684c1ef7f5ffbd90d7b7f52e70a5bcaf0b41",
    "e97a67150cc5ba403e3e977b5231a3376112e5417fb76d0f296c7791c57f5875",
    "02fd242c2caa2cc6e7489e2aa5413bc22610fbd516015e7082f58a5b41e15455",
    "33cf669dcd051880a5d2d0db21a22c209119715bc04b9daf3fff72f8c724c542",
    "209fe58fc21fc09a2d0d5f35c62f941e6476dcd24ac57f5bf1b6d0688e32629a",
    "289deed94031da7c720304462e3cda5cf6512ea55f5b9781411b88c22a398e08",
    "d9dc43892b1f61e630c2b33dccf16122afb258e08cd2b97ad42b1e8e7ffc0816",
    "937a6f3b10964b869053f1b9e89105f3584dd81f395d7ad214239c042c87df29",
    "8556cc200e5fc87cd961bc5021f4a8f0a9e9883a60a38bbf5d2cf71590500185",
    "9bd265080a413d5cfec8f95955c0a33aee20f52eb8299d9d5f185dcce5e75f30",
    "0553fd852e56f36101b848c58bb147786b3a46e9b742c3b1939854ff20ef8e12",
    "f1c3407922b3a0bbb140c5dfd767db10ce04f42078d92b0713c3bd0a501b3275",
    "db7d6da158dbf1d29641db69f64e3ce619351873e179174d76381968aaeb7b03",
    "31d6bdfbcfad0d47589eb4ccb6a7b4e5940ee4e0cc1c752d1c0c26c5979c5c5c",
    "817dd96f69c23b62ea4d706ccffc8d032d1629807619ecefd78259ce29875865",
    "0fb11c0e7e4cc52475f3155e53ea5d863b1b8ef8ea1646dbb333a05002490a3b",
};

int32_t safecoin_bannedset(int32_t *indallvoutsp,uint256 *array,int32_t max)
{
    int32_t i;
    if ( sizeof(banned_txids)/sizeof(*banned_txids) > max )
    {
        fprintf(stderr,"safecoin_bannedset: buffer too small %ld vs %d\n",sizeof(banned_txids)/sizeof(*banned_txids),max);
        exit(-1);
    }
    for (i=0; i<sizeof(banned_txids)/sizeof(*banned_txids); i++)
        array[i] = uint256S(banned_txids[i]);
    *indallvoutsp = i-2;
    return i;
}

void safecoin_passport_iteration();

int8_t safecoin_check_deposit(int32_t height,const CBlock& block,uint32_t prevtime) // verify above block is valid pax pricing
{
    static uint256 array[64]; static int32_t numbanned,indallvouts;
    int32_t i,j,k,n,ht,baseid,txn_count,activation,num,opretlen,offset=1,errs=0,matched=0,safeheights[256],otherheights[256]; uint256 hash,txids[256]; char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],base[SAFECOIN_ASSETCHAIN_MAXLEN]; uint16_t vouts[256]; int8_t baseids[256]; uint8_t *script,opcode,rmd160s[256*20]; uint64_t total,subsidy,available,deposited,issued,withdrawn,approved,redeemed,seed; int64_t checktoshis,values[256],srcvalues[256]; struct pax_transaction *pax; struct safecoin_state *sp; CTransaction tx; bool notmatched=false;
    activation = 235300;
    if ( *(int32_t *)&array[0] == 0 )
        numbanned = safecoin_bannedset(&indallvouts,array,(int32_t)(sizeof(array)/sizeof(*array)));
    memset(baseids,0xff,sizeof(baseids));
    memset(values,0,sizeof(values));
    memset(srcvalues,0,sizeof(srcvalues));
    memset(rmd160s,0,sizeof(rmd160s));
    memset(safeheights,0,sizeof(safeheights));
    memset(otherheights,0,sizeof(otherheights));
    if ( ASSETCHAINS_SYMBOL[0] == '\0' )
    {
        for (i=0; i<block.vtx.size(); i++)
        {
            if ( i == 0 && txn_count > 1 && block.vtx.back().vout.size() > 0 && block.vtx.back().vout[0].nValue == 5000 )
                notmatched = block.vtx.back().vin.size() == 1 && GetTransaction(block.vtx.back().vin[0].prevout.hash,tx,hash,false) && block.vtx[0].vout[0].scriptPubKey == tx.vout[block.vtx.back().vin[0].prevout.n].scriptPubKey;
            n = block.vtx[i].vin.size();
            for (j=0; j<n; j++)
            {
                for (k=0; k<numbanned; k++)
                {
                    if ( block.vtx[i].vin[j].prevout.hash == array[k] && (block.vtx[i].vin[j].prevout.n == 1 || k >= indallvouts)  )
                    {
                        printf("banned tx.%d being used at ht.%d txi.%d vini.%d\n",k,height,i,j);
                        return -1;
                    }
                }
            }
        }
    }
    // we don't want these checks in VRSC, leave it at the Sapling upgrade
    if ( ASSETCHAINS_SYMBOL[0] == '\0' ||
         (ASSETCHAINS_COMMISSION != 0 && height > 1) ||
         NetworkUpgradeActive(height, Params().GetConsensus(), Consensus::UPGRADE_SAPLING) )
    {
        n = block.vtx[0].vout.size();
        int64_t val,prevtotal = 0; int32_t strangeout=0,overflow = 0;
        total = 0;
        for (i=1; i<n; i++)
        {
            script = (uint8_t *)&block.vtx[0].vout[i].scriptPubKey[0];
            if ( (val= block.vtx[0].vout[i].nValue) < 0 || val >= MAX_MONEY )
            {
                overflow = 1;
                break;
            }
            if ( i > 1 && script[0] != 0x6a && val < 5000 )
                ++strangeout;
            total += val;
            if ( total < prevtotal || (val != 0 && total == prevtotal) )
            {
                overflow = 1;
                break;
            }
            prevtotal = total;
        }
        if ( ASSETCHAINS_SYMBOL[0] == '\0' )
        {
            if ( overflow != 0 || total > COIN/10 )
            {
                if ( height >= activation )
                {
                    if ( height > 800000 )
                        fprintf(stderr,">>>>>>>> <<<<<<<<<< ht.%d illegal nonz output %.8f n.%d\n",height,dstr(block.vtx[0].vout[1].nValue),n);
                    return -1;
                }
            }
            else if ( block.nBits == SAFECOIN_MINDIFF_NBITS && total > 0 ) // to deal with fee stealing
            {
                fprintf(stderr,"notary mined ht.%d with extra %.8f\n",height,dstr(total));
                if ( height > SAFECOIN_NOTARIES_HEIGHT1 )
                    return -1;
            }
            if ( strangeout != 0 || notmatched != 0 )
            {
                if ( 0 && strcmp(NOTARY_PUBKEY.c_str(),"03b7621b44118017a16043f19b30cc8a4cfe068ac4e42417bae16ba460c80f3828") == 0 )
                    fprintf(stderr,">>>>>>>>>>>>> DUST ht.%d strangout.%d notmatched.%d <<<<<<<<<\n",height,strangeout,notmatched);
                if ( height > 1000000 && strangeout != 0 )
                    return -1;
            }
            else if ( height > 814000 )
            {
                script = (uint8_t *)&block.vtx[0].vout[0].scriptPubKey[0];
                return height > 1000000 && safecoin_electednotary(&num,script+1,height,0) >= 0 ? -1 : 0;
            }
        }
        else
        {
            checktoshis = 0;
            if ( ASSETCHAINS_COMMISSION != 0 && height > 1 )
            {
                if ( (checktoshis= safecoin_checkcommission((CBlock *)&block,height)) < 0 )
                {
                    fprintf(stderr,"ht.%d checktoshis %.8f overflow.%d total %.8f strangeout.%d\n",height,dstr(checktoshis),overflow,dstr(total),strangeout);
                    return -1;
                }
            }
            if ( height > 1 && checktoshis == 0 )
            {
                checktoshis = ((uint64_t)GetBlockSubsidy(height, Params().GetConsensus()) - block.vtx[0].vout[0].nValue);
                // some pools will need to change their pool fee to be (poolfee % - txfees)
                //checktoshis += txn_count * 0.001; // rely on higher level validations to prevent emitting more coins than actual txfees
            }
            if ( height >= 2 && (overflow != 0 || total > checktoshis || strangeout != 0) )
            {
                fprintf(stderr,"checkdeposit: ht.%d checktoshis %.8f overflow.%d total %.8f strangeout.%d\n",height,dstr(checktoshis),overflow,dstr(total),strangeout);
                if ( strangeout != 0 )
                    fprintf(stderr,">>>>>>>>>>>>> %s DUST ht.%d strangeout.%d notmatched.%d <<<<<<<<<\n",ASSETCHAINS_SYMBOL,height,strangeout,notmatched);
                return -1;
            }
        }
    }
    return 0;
}

const char *safecoin_opreturn(int32_t height,uint64_t value,uint8_t *opretbuf,int32_t opretlen,uint256 txid,uint16_t vout,char *source)
{
    uint8_t rmd160[20],rmd160s[64*20],addrtype,shortflag,pubkey33[33]; int32_t i,j,n,kvheight,len,safeheight,otherheights[64],safeheights[64]; int8_t baseids[64]; char base[4],coinaddr[64],destaddr[64]; uint256 txids[64]; uint16_t vouts[64]; uint64_t convtoshis,seed; int64_t fee,fiatoshis,safecoinshis,checktoshis,values[64],srcvalues[64]; struct pax_transaction *pax,*pax2; struct safecoin_state *basesp; double diff; bool didstats,tosafecoin;
    const char *typestr = "unknown";
    if ( ASSETCHAINS_SYMBOL[0] != '\0' && safecoin_baseid(ASSETCHAINS_SYMBOL) == -1 && opretbuf[0] != 'K' )
    {
        //printf("safecoin_opreturn skip %s\n",ASSETCHAINS_SYMBOL);
        return "assetchain";
    }
    memset(baseids,0xff,sizeof(baseids));
    memset(values,0,sizeof(values));
    memset(srcvalues,0,sizeof(srcvalues));
    memset(rmd160s,0,sizeof(rmd160s));
    memset(safeheights,0,sizeof(safeheights));
    memset(otherheights,0,sizeof(otherheights));
    tosafecoin = !safecoin_is_issuer();
    if ( opretbuf[0] == 'K' && opretlen != 40 )
    {
        safecoin_kvupdate(opretbuf,opretlen,value);
        return "kv";
    }
    else if ( ASSETCHAINS_SYMBOL[0] == '\0' && SAFECOIN_PAX == 0 )
        return "nopax";
    if ( opretbuf[0] == 'D' )
    {
        tosafecoin = false;
        if ( opretlen == 38 ) // any SAFE tx
        {
            iguana_rwnum(0,&opretbuf[34],sizeof(safeheight),&safeheight);
            memset(base,0,sizeof(base));
            PAX_pubkey(0,&opretbuf[1],&addrtype,rmd160,base,&shortflag,&fiatoshis);
            bitcoin_address(coinaddr,addrtype,rmd160,20);
            checktoshis = PAX_fiatdest(&seed,tosafecoin,destaddr,pubkey33,coinaddr,safeheight,base,fiatoshis);
            if ( safecoin_paxcmp(base,safeheight,value,checktoshis,safeheight < 225000 ? seed : 0) != 0 )
                checktoshis = PAX_fiatdest(&seed,tosafecoin,destaddr,pubkey33,coinaddr,height,base,fiatoshis);
            typestr = "deposit";
            if ( 0 && strcmp("NOK",base) == 0 )
            {
                printf("[%s] %s paxdeposit height.%d vs safeheight.%d\n",ASSETCHAINS_SYMBOL,base,height,safeheight);
                printf("(%s) (%s) safeheight.%d vs height.%d check %.8f vs %.8f tosafecoin.%d %d seed.%llx\n",ASSETCHAINS_SYMBOL,base,safeheight,height,dstr(checktoshis),dstr(value),safecoin_is_issuer(),strncmp(ASSETCHAINS_SYMBOL,base,strlen(base)) == 0,(long long)seed);
                for (i=0; i<32; i++)
                    printf("%02x",((uint8_t *)&txid)[i]);
                printf(" <- txid.v%u ",vout);
                for (i=0; i<33; i++)
                    printf("%02x",pubkey33[i]);
                printf(" checkpubkey check %.8f v %.8f dest.(%s) safeheight.%d height.%d\n",dstr(checktoshis),dstr(value),destaddr,safeheight,height);
            }
            if ( strcmp(base,ASSETCHAINS_SYMBOL) == 0 && (safeheight > 195000 || safeheight <= height) )
            {
                didstats = false;
                if ( safecoin_paxcmp(base,safeheight,value,checktoshis,safeheight < 225000 ? seed : 0) == 0 )
                {
                    if ( (pax= safecoin_paxfind(txid,vout,'D')) == nullptr )
                    {
                        if ( (basesp= safecoin_stateptrget(base)) != nullptr )
                        {
                            basesp->deposited += fiatoshis;
                            didstats = true;
                            if ( 0 && strcmp(base,ASSETCHAINS_SYMBOL) == 0 )
                                printf("########### %p deposited %s += %.8f safeheight.%d %.8f\n",basesp,base,dstr(fiatoshis),safeheight,dstr(value));
                        } else printf("cant get stateptr.(%s)\n",base);
                        safecoin_gateway_deposit(coinaddr,value,base,fiatoshis,rmd160,txid,vout,'D',safeheight,height,(char *)"SAFE",0);
                    }
                    if ( (pax= safecoin_paxfind(txid,vout,'D')) != nullptr )
                    {
                        pax->height = safeheight;
                        pax->validated = value;
                        pax->safecoinshis = value;
                        pax->fiatoshis = fiatoshis;
                        if ( !didstats && !pax->didstats )
                        {
                            if ( (basesp= safecoin_stateptrget(base)) != nullptr )
                            {
                                basesp->deposited += fiatoshis;
                                didstats = true;
                                if ( 0 && strcmp(base,ASSETCHAINS_SYMBOL) == 0 )
                                    printf("########### %p depositedB %s += %.8f/%.8f safeheight.%d/%d %.8f/%.8f\n",basesp,base,dstr(fiatoshis),dstr(pax->fiatoshis),safeheight,pax->height,dstr(value),dstr(pax->safecoinshis));
                            }
                        } //
                        if ( didstats )
                            pax->didstats = true;
                        if ( (pax2= safecoin_paxfind(txid,vout,'I')) != nullptr )
                        {
                            pax2->fiatoshis = pax->fiatoshis;
                            pax2->safecoinshis = pax->safecoinshis;
                            pax->marked = pax2->marked = pax->height;
                            pax2->height = pax->height = height;
                            if ( !pax2->didstats )
                            {
                                if ( (basesp= safecoin_stateptrget(base)) != nullptr )
                                {
                                    basesp->issued += pax2->fiatoshis;
                                    pax2->didstats = true;
                                    if ( 0 && strcmp(base,"USD") == 0 )
                                        printf("########### %p issueda %s += %.8f safeheight.%d %.8f other.%d [%d]\n",basesp,base,dstr(pax2->fiatoshis),pax2->height,dstr(pax2->safecoinshis),pax2->otherheight,height);
                                }
                            }
                        }
                    }
                }
                else
                {
                    if ( (pax= safecoin_paxfind(txid,vout,'D')) != nullptr )
                        pax->marked = checktoshis;
                    if ( safeheight > 238000 && (safeheight > 214700 || strcmp(base,ASSETCHAINS_SYMBOL) == 0) ) //seed != 0 &&
                        printf("pax %s deposit %.8f rejected safeheight.%d %.8f SAFE check %.8f seed.%llu\n",base,dstr(fiatoshis),safeheight,dstr(value),dstr(checktoshis),(long long)seed);
                }
            } //else printf("[%s] %s paxdeposit height.%d vs safeheight.%d\n",ASSETCHAINS_SYMBOL,base,height,safeheight);
        } //else printf("unsupported size.%d for opreturn D\n",opretlen);
    }
    else if ( opretbuf[0] == 'I' )
    {
        tosafecoin = false;
        if ( strncmp((char *)"SAFE",(char *)&opretbuf[opretlen-4],3) != 0 && strncmp(ASSETCHAINS_SYMBOL,(char *)&opretbuf[opretlen-4],3) == 0 )
        {
            if ( (n= safecoin_issued_opreturn(base,txids,vouts,values,srcvalues,safeheights,otherheights,baseids,rmd160s,opretbuf,opretlen,false)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( baseids[i] < 0 )
                    {
                        static uint32_t counter;
                        if ( counter++ < 0 )
                            printf("%d of %d illegal baseid.%d, this can be ignored\n",i,n,baseids[i]);
                        continue;
                    }
                    bitcoin_address(coinaddr,60,&rmd160s[i*20],20);
                    safecoin_gateway_deposit(coinaddr,0,ASSETCHAINS_SYMBOL,0,0,txids[i],vouts[i],'I',height,0,CURRENCIES[baseids[i]],0);
                    safecoin_paxmark(height,txids[i],vouts[i],'I',height);
                    if ( (pax= safecoin_paxfind(txids[i],vouts[i],'I')) != nullptr )
                    {
                        pax->type = opretbuf[0];
                        strcpy(pax->source,(char *)&opretbuf[opretlen-4]);
                        if ( (pax2= safecoin_paxfind(txids[i],vouts[i],'D')) != nullptr && pax2->fiatoshis != 0 && pax2->safecoinshis != 0 )
                        {
                            // realtime path?
                            pax->fiatoshis = pax2->fiatoshis;
                            pax->safecoinshis = pax2->safecoinshis;
                            pax->marked = pax2->marked = pax2->height;
                            if ( !pax->didstats )
                            {
                                if ( (basesp= safecoin_stateptrget(CURRENCIES[baseids[i]])) != nullptr )
                                {
                                    basesp->issued += pax->fiatoshis;
                                    pax->didstats = true;
                                    pax->height = pax2->height;
                                    pax->otherheight = height;
                                    if ( 1 && strcmp(CURRENCIES[baseids[i]],"USD") == 0 )
                                        printf("########### %p issuedb %s += %.8f safeheight.%d %.8f other.%d [%d]\n",basesp,CURRENCIES[baseids[i]],dstr(pax->fiatoshis),pax->height,dstr(pax->safecoinshis),pax->otherheight,height);
                                }
                            }
                        }
                    }
                    if ( (pax= safecoin_paxmark(height,txids[i],vouts[i],'I',height)) != nullptr )
                        safecoin_paxdelete(pax);
                    if ( (pax= safecoin_paxmark(height,txids[i],vouts[i],'D',height)) != nullptr )
                        safecoin_paxdelete(pax);
                }
            } //else printf("opreturn none issued?\n");
        }
    }
    else if ( height < 236000 && opretbuf[0] == 'W' && strncmp(ASSETCHAINS_SYMBOL,(char *)&opretbuf[opretlen-4],3) == 0 )//&& opretlen >= 38 )
    {
        if ( safecoin_baseid((char *)&opretbuf[opretlen-4]) != -1 && strcmp(ASSETCHAINS_SYMBOL,(char *)&opretbuf[opretlen-4]) == 0 )
        {
            for (i=0; i<opretlen; i++)
                printf("%02x",opretbuf[i]);
            printf(" [%s] reject obsolete withdraw request.%s\n",ASSETCHAINS_SYMBOL,(char *)&opretbuf[opretlen-4]);
            return typestr;
        }
        tosafecoin = true;
        iguana_rwnum(0,&opretbuf[34],sizeof(safeheight),&safeheight);
        memset(base,0,sizeof(base));
        PAX_pubkey(0,&opretbuf[1],&addrtype,rmd160,base,&shortflag,&safecoinshis);
        bitcoin_address(coinaddr,addrtype,rmd160,20);
        checktoshis = PAX_fiatdest(&seed,tosafecoin,destaddr,pubkey33,coinaddr,safeheight,base,value);
        typestr = "withdraw";
        //printf(" [%s] WITHDRAW %s.height.%d vs height.%d check %.8f/%.8f vs %.8f tosafecoin.%d %d seed.%llx -> (%s) len.%d\n",ASSETCHAINS_SYMBOL,base,safeheight,height,dstr(checktoshis),dstr(safecoinshis),dstr(value),safecoin_is_issuer(),strncmp(ASSETCHAINS_SYMBOL,base,strlen(base)) == 0,(long long)seed,coinaddr,opretlen);
        didstats = false;
        //if ( safecoin_paxcmp(base,safeheight,safecoinshis,checktoshis,seed) == 0 )
        {
            if ( value != 0 && ((pax= safecoin_paxfind(txid,vout,'W')) == nullptr || !pax->didstats) )
            {
                if ( (basesp= safecoin_stateptrget(base)) != nullptr )
                {
                    basesp->withdrawn += value;
                    didstats = true;
                    if ( 0 && strcmp(base,ASSETCHAINS_SYMBOL) == 0 )
                        printf("########### %p withdrawn %s += %.8f check %.8f\n",basesp,base,dstr(value),dstr(checktoshis));
                }
                if ( 0 && strcmp(base,"RUB") == 0 && (pax == 0 || pax->approved == 0) )
                    printf("notarize %s %.8f -> %.8f safe.%d other.%d\n",ASSETCHAINS_SYMBOL,dstr(value),dstr(safecoinshis),safeheight,height);
            }
            safecoin_gateway_deposit(coinaddr,0,(char *)"SAFE",value,rmd160,txid,vout,'W',safeheight,height,source,0);
            if ( (pax= safecoin_paxfind(txid,vout,'W')) != nullptr )
            {
                pax->type = opretbuf[0];
                strcpy(pax->source,base);
                strcpy(pax->symbol,"SAFE");
                pax->height = safeheight;
                pax->otherheight = height;
                pax->safecoinshis = safecoinshis;
            }
        } // else printf("withdraw %s paxcmp ht.%d %d error value %.8f -> %.8f vs %.8f\n",base,safeheight,height,dstr(value),dstr(safecoinshis),dstr(checktoshis));
        // need to allocate pax
    }
    else if ( height < 236000 && tosafecoin && opretbuf[0] == 'A' && ASSETCHAINS_SYMBOL[0] == '\0' )
    {
        if ( 0 && ASSETCHAINS_SYMBOL[0] != '\0' )
        {
            for (i=0; i<opretlen; i++)
                printf("%02x",opretbuf[i]);
            printf(" opret[%c] else path tosafecoin.%d ht.%d before %.8f opretlen.%d\n",opretbuf[0],tosafecoin,height,dstr(safecoin_paxtotal()),opretlen);
        }
        if ( (n= safecoin_issued_opreturn(base,txids,vouts,values,srcvalues,safeheights,otherheights,baseids,rmd160s,opretbuf,opretlen,true)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                //for (j=0; j<32; j++)
                //    printf("%02x",((uint8_t *)&txids[i])[j]);
                //printf(" v%d %.8f %.8f k.%d ht.%d base.%d\n",vouts[i],dstr(values[i]),dstr(srcvalues[i]),safeheights[i],otherheights[i],baseids[i]);
                if ( baseids[i] < 0 )
                {
                    for (i=0; i<opretlen; i++)
                        printf("%02x",opretbuf[i]);
                    printf(" opret[%c] else path tosafecoin.%d ht.%d before %.8f opretlen.%d\n",opretbuf[0],tosafecoin,height,dstr(safecoin_paxtotal()),opretlen);
                    //printf("baseids[%d] %d\n",i,baseids[i]);
                    if ( (pax= safecoin_paxfind(txids[i],vouts[i],'W')) != 0 || (pax= safecoin_paxfind(txids[i],vouts[i],'X')) != 0 )
                    {
                        baseids[i] = safecoin_baseid(pax->symbol);
                        printf("override neg1 with (%s)\n",pax->symbol);
                    }
                    if ( baseids[i] < 0 )
                        continue;
                }
                didstats = false;
                seed = 0;
                checktoshis = safecoin_paxprice(&seed,safeheights[i],CURRENCIES[baseids[i]],(char *)"SAFE",(uint64_t)values[i]);
                //printf("PAX_fiatdest ht.%d price %s %.8f -> SAFE %.8f vs %.8f\n",safeheights[i],CURRENCIES[baseids[i]],(double)values[i]/COIN,(double)srcvalues[i]/COIN,(double)checktoshis/COIN);
                if ( srcvalues[i] == checktoshis )
                {
                    if ( (pax= safecoin_paxfind(txids[i],vouts[i],'A')) == nullptr )
                    {
                        bitcoin_address(coinaddr,60,&rmd160s[i*20],20);
                        safecoin_gateway_deposit(coinaddr,srcvalues[i],CURRENCIES[baseids[i]],values[i],&rmd160s[i*20],txids[i],vouts[i],'A',safeheights[i],otherheights[i],CURRENCIES[baseids[i]],safeheights[i]);
                        if ( (pax= safecoin_paxfind(txids[i],vouts[i],'A')) == nullptr )
                            printf("unexpected null pax for approve\n");
                        else pax->validated = checktoshis;
                        if ( (pax2= safecoin_paxfind(txids[i],vouts[i],'W')) != nullptr )
                            pax2->approved = safeheights[i];
                        safecoin_paxmark(height,txids[i],vouts[i],'W',height);
                        //safecoin_paxmark(height,txids[i],vouts[i],'A',height);
                        if ( values[i] != 0 && (basesp= safecoin_stateptrget(CURRENCIES[baseids[i]])) != nullptr )
                        {
                            basesp->approved += values[i];
                            didstats = true;
                            //printf("pax.%p ########### %p approved %s += %.8f -> %.8f/%.8f kht.%d %d\n",pax,basesp,CURRENCIES[baseids[i]],dstr(values[i]),dstr(srcvalues[i]),dstr(checktoshis),safeheights[i],otherheights[i]);
                        }
                        //printf(" i.%d (%s) <- %.8f ADDFLAG APPROVED\n",i,coinaddr,dstr(values[i]));
                    }
                    else if ( !pax->didstats && srcvalues[i] != 0 )
                    {
                        if ( (basesp= safecoin_stateptrget(CURRENCIES[baseids[i]])) != nullptr )
                        {
                            basesp->approved += values[i];
                            didstats = true;
                            //printf("pax.%p ########### %p approved %s += %.8f -> %.8f/%.8f kht.%d %d\n",pax,basesp,CURRENCIES[baseids[i]],dstr(values[i]),dstr(srcvalues[i]),dstr(checktoshis),safeheights[i],otherheights[i]);
                        }
                    } //else printf(" i.%d of n.%d pax.%p baseids[] %d\n",i,n,pax,baseids[i]);
                    if ( (pax= safecoin_paxfind(txids[i],vouts[i],'A')) != nullptr )
                    {
                        pax->type = opretbuf[0];
                        pax->approved = safeheights[i];
                        pax->validated = checktoshis;
                        if ( didstats )
                            pax->didstats = true;
                        //if ( strcmp(CURRENCIES[baseids[i]],ASSETCHAINS_SYMBOL) == 0 )
                        //printf(" i.%d approved.%d <<<<<<<<<<<<< APPROVED %p\n",i,safeheights[i],pax);
                    }
                }
            }
        } //else printf("n.%d from opreturns\n",n);
        //printf("extra.[%d] after %.8f\n",n,dstr(safecoin_paxtotal()));
    }
    else if ( height < 236000 && opretbuf[0] == 'X' && ASSETCHAINS_SYMBOL[0] == '\0' )
    {
        tosafecoin = true;
        if ( (n= safecoin_issued_opreturn(base,txids,vouts,values,srcvalues,safeheights,otherheights,baseids,rmd160s,opretbuf,opretlen,true)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                if ( baseids[i] < 0 )
                    continue;
                bitcoin_address(coinaddr,60,&rmd160s[i*20],20);
                safecoin_gateway_deposit(coinaddr,0,0,0,0,txids[i],vouts[i],'X',height,0,(char *)"SAFE",0);
                safecoin_paxmark(height,txids[i],vouts[i],'W',height);
                safecoin_paxmark(height,txids[i],vouts[i],'A',height);
                safecoin_paxmark(height,txids[i],vouts[i],'X',height);
                if ( (pax= safecoin_paxfind(txids[i],vouts[i],'X')) != nullptr )
                {
                    pax->type = opretbuf[0];
                    if ( height < 121842 ) // fields got switched around due to legacy issues and approves
                        value = srcvalues[i];
                    else value = values[i];
                    if ( baseids[i] >= 0 && value != 0 && (basesp= safecoin_stateptrget(CURRENCIES[baseids[i]])) != nullptr )
                    {
                        basesp->redeemed += value;
                        pax->didstats = true;
                        if ( strcmp(CURRENCIES[baseids[i]],ASSETCHAINS_SYMBOL) == 0 )
                            printf("ht.%d %.8f ########### %p redeemed %s += %.8f %.8f kht.%d ht.%d\n",height,dstr(value),basesp,CURRENCIES[baseids[i]],dstr(value),dstr(srcvalues[i]),safeheights[i],otherheights[i]);
                    }
                }
                if ( (pax= safecoin_paxmark(height,txids[i],vouts[i],'W',height)) != nullptr )
                    safecoin_paxdelete(pax);
                if ( (pax= safecoin_paxmark(height,txids[i],vouts[i],'A',height)) != nullptr )
                    safecoin_paxdelete(pax);
                if ( (pax= safecoin_paxmark(height,txids[i],vouts[i],'X',height)) != nullptr )
                    safecoin_paxdelete(pax);
            }
        } //else printf("safecoin_issued_opreturn returned %d\n",n);
    }
    return typestr;
}

int32_t safecoin_parsestatefiledata(struct safecoin_state *sp,uint8_t *filedata,long *fposp,long datalen,char *symbol,char *dest);

void safecoin_stateind_set(struct safecoin_state *sp,uint32_t *inds,int32_t n,uint8_t *filedata,long datalen,char *symbol,char *dest)
{
    uint8_t func; long lastK,lastT,lastN,lastV,fpos,lastfpos; int32_t i,count,iter,numn,numv,numN,numV,numR; uint32_t tmp,prevpos100,offset; bool doissue;
    count = numR = numN = numV = numn = numv = 0;
    lastK = lastT = lastN = lastV = -1;
    for (iter=0; iter<2; iter++)
    {
        for (lastfpos=fpos=prevpos100=i=0; i<n; i++)
        {
            tmp = inds[i];
            if ( i % 100 == 0 )
                prevpos100 = tmp;
            else
            {
                func = tmp & 0xff;
                offset = tmp >> 8;
                fpos = prevpos100 + offset;
                if ( lastfpos >= datalen || (filedata[lastfpos] != func && func != 0) )
                    printf("i.%d/n.%d lastfpos.%ld >= datalen.%ld or [%d] != func.%d\n",i,n,lastfpos,datalen,filedata[lastfpos],func);
                else if ( iter == 0 )
                {
                    switch ( func )
                    {
                        default: case 'P': case 'U': case 'D':
                            inds[i] &= 0xffffff00;
                            break;
                        case 'K':
                            lastK = lastfpos;
                            inds[i] &= 0xffffff00;
                            break;
                        case 'T':
                            lastT = lastfpos;
                            inds[i] &= 0xffffff00;
                            break;
                        case 'N':
                            lastN = lastfpos;
                            ++numN;
                            break;
                        case 'V':
                            lastV = lastfpos;
                            ++numV;
                            break;
                        case 'R':
                            ++numR;
                            break;
                    }
                }
                else
                {
                    doissue = false;
                    if ( func == 'K' )
                        doissue = lastK == lastfpos;
                    else if ( func == 'T' )
                        doissue = lastT == lastfpos;
                    else if ( func == 'N' )
                        doissue = numn++ > numN-128;
                    else if ( func == 'V' )
                        doissue = SAFECOIN_PAX != 0 && numv++ > numV-1440;
                    else if ( func == 'R' )
                        doissue = true;
                    if ( doissue )
                    {
                        //printf("issue %c total.%d lastfpos.%ld\n",func,count,lastfpos);
                        safecoin_parsestatefiledata(sp,filedata,&lastfpos,datalen,symbol,dest);
                        ++count;
                    }
                }
            }
            lastfpos = fpos;
        }
    }
    printf("numR.%d numV.%d numN.%d count.%d\n",numR,numV,numN,count);
    /*else if ( func == 'K' ) // SAFE height: stop after 1st
    else if ( func == 'T' ) // SAFE height+timestamp: stop after 1st

    else if ( func == 'N' ) // notarization, scan backwards 1440+ blocks;
    else if ( func == 'V' ) // price feed: can stop after 1440+
    else if ( func == 'R' ) // opreturn:*/
}

void *OS_loadfile(char *fname,uint8_t **bufp,long *lenp,long *allocsizep)
{
    FILE *fp;
    long  filesize,buflen = *allocsizep;
    uint8_t *buf = *bufp;
    *lenp = 0;
    if ( (fp= fopen(fname,"rb")) != nullptr )
    {
        fseek(fp,0,SEEK_END);
        filesize = ftell(fp);
        if ( filesize == 0 )
        {
            fclose(fp);
            *lenp = 0;
            printf("OS_loadfile null size.(%s)\n",fname);
            return(0);
        }
        if ( filesize > buflen )
        {
            *allocsizep = filesize;
            *bufp = buf = (uint8_t *)realloc(buf,(long)*allocsizep+64);
        }
        rewind(fp);
        if ( buf == nullptr )
            printf("Null buf ???\n");
        else
        {
            if ( fread(buf,1,(long)filesize,fp) != (unsigned long)filesize )
                printf("error reading filesize.%ld\n",(long)filesize);
            buf[filesize] = 0;
        }
        fclose(fp);
        *lenp = filesize;
        //printf("loaded.(%s)\n",buf);
    } //else printf("OS_loadfile couldnt load.(%s)\n",fname);
    return buf;
}

uint8_t *OS_fileptr(long *allocsizep,char *fname)
{
    long filesize = 0; uint8_t *buf = 0; void *retptr;
    *allocsizep = 0;
    retptr = OS_loadfile(fname,&buf,&filesize,allocsizep);
    return (uint8_t *)retptr;
}

long safecoin_stateind_validate(struct safecoin_state *sp,char *indfname,uint8_t *filedata,long datalen,uint32_t *prevpos100p,uint32_t *indcounterp,char *symbol,char *dest)
{
    FILE *fp; long fsize,lastfpos=0,fpos=0; uint8_t *inds,func; int32_t i,n; uint32_t offset,tmp,prevpos100 = 0;
    *indcounterp = *prevpos100p = 0;
    if ( (inds= OS_fileptr(&fsize,indfname)) != nullptr )
    {
        lastfpos = 0;
        fprintf(stderr,"inds.%p validate %s fsize.%ld datalen.%ld n.%ld lastfpos.%ld\n",inds,indfname,fsize,datalen,fsize / sizeof(uint32_t),lastfpos);
        if ( (fsize % sizeof(uint32_t)) == 0 )
        {
            n = (int32_t)(fsize / sizeof(uint32_t));
            for (i=0; i<n; i++)
            {
                memcpy(&tmp,&inds[i * sizeof(uint32_t)],sizeof(uint32_t));
                if ( 0 && i > n-10 )
                    printf("%d: tmp.%08x [%c] prevpos100.%u\n",i,tmp,tmp&0xff,prevpos100);
                if ( (i % 100) == 0 )
                    prevpos100 = tmp;
                else
                {
                    func = (tmp & 0xff);
                    offset = (tmp >> 8);
                    fpos = prevpos100 + offset;
                    if ( lastfpos >= datalen || filedata[lastfpos] != func )
                    {
                        printf("validate.%d error (%u %d) prev100 %u -> fpos.%ld datalen.%ld [%d] (%c) vs (%c) lastfpos.%ld\n",i,offset,func,prevpos100,fpos,datalen,lastfpos < datalen ? filedata[lastfpos] : -1,func,filedata[lastfpos],lastfpos);
                        return -1;
                    }
                }
                lastfpos = fpos;
            }
            *indcounterp = n;
            *prevpos100p = prevpos100;
            if ( sp != nullptr )
                safecoin_stateind_set(sp,(uint32_t *)inds,n,filedata,fpos,symbol,dest);
            //printf("free inds.%p %s validated[%d] fpos.%ld datalen.%ld, offset %ld vs fsize.%ld\n",inds,indfname,i,fpos,datalen,i * sizeof(uint32_t),fsize);
            free(inds);
            return fpos;
        } else printf("wrong filesize %s %ld\n",indfname,fsize);
    }
    free(inds);
    fprintf(stderr,"indvalidate return -1\n");
    return -1;
}

long safecoin_indfile_update(FILE *indfp,uint32_t *prevpos100p,long lastfpos,long newfpos,uint8_t func,uint32_t *indcounterp)
{
    uint32_t tmp;
    if ( indfp != nullptr )
    {
        tmp = ((uint32_t)(newfpos - *prevpos100p) << 8) | (func & 0xff);
        if ( ftell(indfp)/sizeof(uint32_t) != *indcounterp )
            printf("indfp fpos %ld -> ind.%ld vs counter.%u\n",ftell(indfp),ftell(indfp)/sizeof(uint32_t),*indcounterp);
        //fprintf(stderr,"ftell.%ld indcounter.%u lastfpos.%ld newfpos.%ld func.%02x\n",ftell(indfp),*indcounterp,lastfpos,newfpos,func);
        fwrite(&tmp,1,sizeof(tmp),indfp), (*indcounterp)++;
        if ( *indcounterp % 100 == 0 )
        {
            *prevpos100p = (uint32_t)newfpos;
            fwrite(prevpos100p,1,sizeof(*prevpos100p),indfp), (*indcounterp)++;
        }
    }
    return newfpos;
}

int8_t safecoin_faststateinit(struct safecoin_state *sp,char *fname,char *symbol,char *dest)
{
    FILE *indfp; char indfname[1024]; uint8_t *filedata; long validated=-1,datalen,fpos,lastfpos; uint32_t tmp,prevpos100,indcounter,starttime; int32_t func; bool finished = false;
    starttime = (uint32_t)time(NULL);
    safecopy(indfname,fname,sizeof(indfname)-4);
    strcat(indfname,".ind");
    if ( (filedata= OS_fileptr(&datalen,fname)) != nullptr )
    {
        // if ( 1 )//datalen >= (1LL << 32) || GetArg("-genind",0) != 0 || (validated= safecoin_stateind_validate(0,indfname,filedata,datalen,&prevpos100,&indcounter,symbol,dest)) < 0 )
        // {
            lastfpos = fpos = 0;
            indcounter = prevpos100 = 0;
            if ( (indfp= fopen(indfname,"wb")) != nullptr )
                fwrite(&prevpos100,1,sizeof(prevpos100),indfp), indcounter++;
            fprintf(stderr,"processing %s %ldKB, validated.%ld\n",fname,datalen/1024,validated);
            while ( (func= safecoin_parsestatefiledata(sp,filedata,&fpos,datalen,symbol,dest)) >= 0 )
                lastfpos = safecoin_indfile_update(indfp,&prevpos100,lastfpos,fpos,func,&indcounter);
            if ( indfp != nullptr )
            {
                fclose(indfp);
                if ( (fpos= safecoin_stateind_validate(0,indfname,filedata,datalen,&prevpos100,&indcounter,symbol,dest)) < 0 )
                    printf("unexpected safecoinstate.ind validate failure %s datalen.%ld\n",indfname,datalen);
                else printf("%s validated fpos.%ld\n",indfname,fpos);
            }
            finished = true;
            fprintf(stderr,"took %d seconds to process %s %ldKB\n",(int32_t)(time(NULL)-starttime),fname,datalen/1024);
        // }
        // else if ( validated > 0 )
        // {
        //     if ( (indfp= fopen(indfname,"rb+")) != 0 )
        //     {
        //         lastfpos = fpos = validated;
        //         fprintf(stderr,"datalen.%ld validated %ld -> indcounter %u, prevpos100 %u offset.%ld\n",datalen,validated,indcounter,prevpos100,indcounter * sizeof(uint32_t));
        //         if ( fpos < datalen )
        //         {
        //             fseek(indfp,indcounter * sizeof(uint32_t),SEEK_SET);
        //             if ( ftell(indfp) == indcounter * sizeof(uint32_t) )
        //             {
        //                 while ( (func= safecoin_parsestatefiledata(sp,filedata,&fpos,datalen,symbol,dest)) >= 0 )
        //                 {
        //                     lastfpos = safecoin_indfile_update(indfp,&prevpos100,lastfpos,fpos,func,&indcounter);
        //                     if ( lastfpos != fpos )
        //                         fprintf(stderr,"unexpected lastfpos.%ld != %ld\n",lastfpos,fpos);
        //                 }
        //             }
        //             fclose(indfp);
        //         }
        //         if ( safecoin_stateind_validate(sp,indfname,filedata,datalen,&prevpos100,&indcounter,symbol,dest) < 0 )
        //             printf("unexpected safecoinstate.ind validate failure %s datalen.%ld\n",indfname,datalen);
        //         else
        //         {
        //             printf("%s validated updated from validated.%ld to %ld new.[%ld] -> indcounter %u, prevpos100 %u offset.%ld | elapsed %d seconds\n",indfname,validated,fpos,fpos-validated,indcounter,prevpos100,indcounter * sizeof(uint32_t),(int32_t)(time(NULL) - starttime));
        //             finished = 1;
        //         }
        //     }
        // } else printf("safecoin_faststateinit unexpected case\n");
        free(filedata);
        return finished;
    }
    return -1;
}

uint64_t safecoin_interestsum();

void safecoin_passport_iteration()
{
    static long lastpos[34]; static char userpass[33][1024]; static uint32_t lasttime,callcounter,lastinterest;
    int32_t maxseconds = 10;
    FILE *fp; uint8_t *filedata; long fpos,datalen,lastfpos; int32_t baseid,limit,n,ht,expired,blocks,longest; struct safecoin_state *sp,*refsp; char *retstr,fname[512],*base,symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; uint32_t buf[3],starttime; cJSON *infoobj,*result; uint64_t RTmask = 0; bool isrealtime; int8_t refid;//CBlockIndex *pindex;
    expired = 0;
    while ( SAFECOIN_INITDONE == 0 )
    {
        fprintf(stderr,"[%s] PASSPORT iteration waiting for SAFECOIN_INITDONE\n",ASSETCHAINS_SYMBOL);
        sleep(3);
    }
    if ( safecoin_chainactive_timestamp() > lastinterest )
    {
        if ( ASSETCHAINS_SYMBOL[0] == '\0' )
            safecoin_interestsum();
        //safecoin_longestchain();
        lastinterest = safecoin_chainactive_timestamp();
    }
    refsp = safecoin_stateptr(symbol,dest);
    if ( ASSETCHAINS_SYMBOL[0] == '\0' || strcmp(ASSETCHAINS_SYMBOL,"SAFECC") == 0 )
    {
        refid = 33;
        limit = 10000000;
        jumblr_iteration();
    }
    else
    {
        limit = 10000000;
        refid = safecoin_baseid(ASSETCHAINS_SYMBOL)+1; // illegal base -> baseid.-1 -> 0
        if ( refid == 0 )
        {
            SAFECOIN_PASSPORT_INITDONE = true;
            return;
        }
    }
    /*if ( SAFECOIN_PAX == 0 )
    {
        SAFECOIN_PASSPORT_INITDONE = true;
        return;
    }*/
    starttime = (uint32_t)time(NULL);
    if ( callcounter++ < 1 )
        limit = 10000;
    lasttime = starttime;
    for (baseid=32; baseid>=0; baseid--)
    {
        if ( time(NULL) >= starttime+maxseconds )
            break;
        sp = nullptr;
        isrealtime = false;
        base = (char *)CURRENCIES[baseid];
        //printf("PASSPORT %s baseid+1 %d refid.%d\n",ASSETCHAINS_SYMBOL,baseid+1,refid);
        if ( baseid+1 != refid ) // only need to import state from a different coin
        {
            if ( baseid == 32 ) // only care about SAFE's state
            {
                refsp->RTmask &= ~(1LL << baseid);
                safecoin_statefname(fname,baseid<32?base:(char *)"",(char *)"safecoinstate");
                safecoin_nameset(symbol,dest,base);
                sp = safecoin_stateptrget(symbol);
                n = 0;
                if ( lastpos[baseid] == 0 && (filedata= OS_fileptr(&datalen,fname)) != nullptr )
                {
                    fpos = 0;
                    fprintf(stderr,"%s processing %s %ldKB\n",ASSETCHAINS_SYMBOL,fname,datalen/1024);
                    while ( safecoin_parsestatefiledata(sp,filedata,&fpos,datalen,symbol,dest) >= 0 )
                        lastfpos = fpos;
                    fprintf(stderr,"%s took %d seconds to process %s %ldKB\n",ASSETCHAINS_SYMBOL,(int32_t)(time(NULL)-starttime),fname,datalen/1024);
                    lastpos[baseid] = lastfpos;
                    free(filedata);
                    filedata = nullptr;
                    datalen = 0;
                }
                else if ( (fp= fopen(fname,"rb")) != nullptr && sp != nullptr )
                {
                    fseek(fp,0,SEEK_END);
                    //fprintf(stderr,"couldnt OS_fileptr(%s), freading %ldKB\n",fname,ftell(fp)/1024);
                    if ( ftell(fp) > lastpos[baseid] )
                    {
                        if ( ASSETCHAINS_SYMBOL[0] != '\0' )
                            printf("%s passport refid.%d %s fname.(%s) base.%s %ld %ld\n",ASSETCHAINS_SYMBOL,refid,symbol,fname,base,ftell(fp),lastpos[baseid]);
                        fseek(fp,lastpos[baseid],SEEK_SET);
                        while ( safecoin_parsestatefile(sp,fp,symbol,dest) >= 0 && n < limit )
                        {
                            if ( n == limit-1 )
                            {
                                if ( time(NULL) < starttime+maxseconds )
                                    n = 0;
                                else
                                {
                                    //printf("expire passport loop %s -> %s at %ld\n",ASSETCHAINS_SYMBOL,base,lastpos[baseid]);
                                    ++expired;
                                }
                            }
                            ++n;
                        }
                        lastpos[baseid] = ftell(fp);
                        if ( 0 && lastpos[baseid] == 0 && strcmp(symbol,"SAFE") == 0 )
                            printf("from.(%s) lastpos[%s] %ld isrt.%d\n",ASSETCHAINS_SYMBOL,CURRENCIES[baseid],lastpos[baseid],safecoin_isrealtime(&ht));
                    } //else fprintf(stderr,"%s.%ld ",CURRENCIES[baseid],ftell(fp));
                    fclose(fp);
                } else fprintf(stderr,"load error.(%s) %p\n",fname,sp);
                safecoin_statefname(fname,baseid<32?base:(char *)"",(char *)"realtime");
                if ( (fp= fopen(fname,"rb")) != nullptr )
                {
                    if ( fread(buf,1,sizeof(buf),fp) == sizeof(buf) )
                    {
                        sp->CURRENT_HEIGHT = buf[0];
                        if ( buf[0] != 0 && buf[0] >= buf[1] && buf[2] > time(NULL)-60 )
                        {
                            isrealtime = true;
                            RTmask |= (1LL << baseid);
                            memcpy(refsp->RTbufs[baseid+1],buf,sizeof(refsp->RTbufs[baseid+1]));
                        }
                        else if ( SAFECOIN_PAX != 0 && time(NULL)-buf[2] > 60 && ASSETCHAINS_SYMBOL[0] != '\0' )
                            fprintf(stderr,"[%s]: %s not RT %u %u %d\n",ASSETCHAINS_SYMBOL,base,buf[0],buf[1],(int32_t)(time(NULL)-buf[2]));
                    } //else fprintf(stderr,"%s size error RT\n",base);
                    fclose(fp);
                } //else fprintf(stderr,"%s open error RT\n",base);
            }
        }
        else
        {
            refsp->RTmask &= ~(1LL << baseid);
            safecoin_statefname(fname,baseid<32?base:(char *)"",(char *)"realtime");
            if ( (fp= fopen(fname,"wb")) != nullptr )
            {
                buf[0] = (uint32_t)chainActive.LastTip()->GetHeight();
                buf[1] = (uint32_t)safecoin_longestchain();
                if ( buf[0] != 0 && buf[0] == buf[1] )
                {
                    buf[2] = (uint32_t)time(NULL);
                    RTmask |= (1LL << baseid);
                    memcpy(refsp->RTbufs[baseid+1],buf,sizeof(refsp->RTbufs[baseid+1]));
                    if ( refid != 0 )
                        memcpy(refsp->RTbufs[0],buf,sizeof(refsp->RTbufs[0]));
                }
                if ( fwrite(buf,1,sizeof(buf),fp) != sizeof(buf) )
                    fprintf(stderr,"[%s] %s error writing realtime\n",ASSETCHAINS_SYMBOL,base);
                fclose(fp);
            } else fprintf(stderr,"%s create error RT\n",base);
        }
        if ( sp != nullptr && !isrealtime )
            refsp->RTbufs[0][2] = 0;
    }
    //safecoin_paxtotal(); // calls safecoin_isrealtime(), which calls safecoin_longestchain()
    refsp->RTmask |= RTmask;
    if ( expired == 0 && !SAFECOIN_PASSPORT_INITDONE )
    {
        SAFECOIN_PASSPORT_INITDONE = true;
        printf("READY for %s RPC calls at %u! done PASSPORT %s refid.%d\n",ASSETCHAINS_SYMBOL,(uint32_t)time(NULL),ASSETCHAINS_SYMBOL,refid);
    }
}

