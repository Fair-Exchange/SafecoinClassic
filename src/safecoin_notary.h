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

#include "safecoin_cJSON.h"

#define SAFECOIN_MAINNET_START 1

const char *Notaries_genesis[][2] =
{
    { "btc_testA", "02566977dc0f2eaf2e7aef467e54bac03e6e0967bd750417b1a1c92bc71a410b9d" },
    { "zec_testA", "03f18e2cbdd0eee1cd054f61b062f8e9e89f0fe8698097882422581852c97ce5a5" },
    { "zen_testA", "03b94e3f3e88448d5e957f5c5f25f16b0e2197b8a91da63c7a210821e96672f686" },
};

const char *Notaries_elected0[][2] =
{
    { "btc_testB", "02849a95c44ef3026d5078119791811ecf795c1673a0f196bfeb9131db421140c4" },
    { "zec_testB", "02f5cb4993f1f2ec18e1733c0ec4f4df44b7a638bf1a3a55f6aa43c54c51cf683b" },
    { "zen_testB", "039846a7ae3bee6390ef7ee95769a7443aa1bb5d7e85afd676ebe7ad7420010135" },
};

//////////  Temporary until SafeNodes release
#define SAFECOIN_NOTARIES_TIMESTAMP1 2525132800 // May 1st 2018 1530921600 // 7/7/2017
#define SAFECOIN_NOTARIES_HEIGHT1 9999999999999 //((814000 / SAFECOIN_ELECTION_GAP) * SAFECOIN_ELECTION_GAP)

const char *Notaries_elected1[][2] =
{
    {"btc_testC", "026d8c25820e902591a5c9ba090d0b2174adefb183ce122eb20eb91cdf1045cc4d" },
    {"zec_testC", "0339d7b59dc7501cc00465c77dafff4cdf5df65511b8199537a1390c9a12b3bbfe" },
    {"zen_testC", "03ba0dd059e200bdc60058be772f1428884a8e7f3d6cd83d1ba07457bb538f64e3" },
};
#define CRYPTO777_PUBSECPSTR "02004a23684b6e12441ac4c913775f4f74584c48a9167d2fb65da6a2ddc9852761"

int32_t safecoin_notaries(uint8_t pubkeys[64][33],int32_t height,uint32_t timestamp)
{
    static uint8_t elected_pubkeys0[64][33],elected_pubkeys1[64][33],did0,did1; static int32_t n0,n1;
    int32_t i,htind,n; uint64_t mask = 0; struct knotary_entry *kp,*tmp;
    if ( timestamp == 0 && ASSETCHAINS_SYMBOL[0] != 0 )
        timestamp = safecoin_heightstamp(height);
    else if ( ASSETCHAINS_SYMBOL[0] == 0 )
        timestamp = 0;
    if ( height >= SAFECOIN_NOTARIES_HARDCODED || ASSETCHAINS_SYMBOL[0] != 0 )
    {
        if ( (timestamp != 0 && timestamp <= SAFECOIN_NOTARIES_TIMESTAMP1) || (ASSETCHAINS_SYMBOL[0] == 0 && height <= SAFECOIN_NOTARIES_HEIGHT1) )
        {
            if ( did0 == 0 )
            {
                n0 = (int32_t)(sizeof(Notaries_elected0)/sizeof(*Notaries_elected0));
                for (i=0; i<n0; i++)
                    decode_hex(elected_pubkeys0[i],33,(char *)Notaries_elected0[i][1]);
                did0 = 1;
            }
            memcpy(pubkeys,elected_pubkeys0,n0 * 33);
            //if ( ASSETCHAINS_SYMBOL[0] != 0 )
            //fprintf(stderr,"%s height.%d t.%u elected.%d notaries\n",ASSETCHAINS_SYMBOL,height,timestamp,n0);
            return(n0);
        }
        else //if ( (timestamp != 0 && timestamp <= SAFECOIN_NOTARIES_TIMESTAMP2) || height <= SAFECOIN_NOTARIES_HEIGHT2 )
        {
            if ( did1 == 0 )
            {
                n1 = (int32_t)(sizeof(Notaries_elected1)/sizeof(*Notaries_elected1));
                for (i=0; i<n1; i++)
                    decode_hex(elected_pubkeys1[i],33,(char *)Notaries_elected1[i][1]);
                if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
                    fprintf(stderr,"%s height.%d t.%u elected.%d notaries2\n",ASSETCHAINS_SYMBOL,height,timestamp,n1);
                did1 = 1;
            }
            memcpy(pubkeys,elected_pubkeys1,n1 * 33);
            return(n1);
        }
    }
    htind = height / SAFECOIN_ELECTION_GAP;
    if ( htind >= SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP )
        htind = (SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP) - 1;
    if ( Pubkeys == 0 )
    {
        safecoin_init(height);
        //printf("Pubkeys.%p htind.%d vs max.%d\n",Pubkeys,htind,SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP);
    }
    pthread_mutex_lock(&safecoin_mutex);
    n = Pubkeys[htind].numnotaries;
    if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
        fprintf(stderr,"%s height.%d t.%u genesis.%d\n",ASSETCHAINS_SYMBOL,height,timestamp,n);
    HASH_ITER(hh,Pubkeys[htind].Notaries,kp,tmp)
    {
        if ( kp->notaryid < n )
        {
            mask |= (1LL << kp->notaryid);
            memcpy(pubkeys[kp->notaryid],kp->pubkey,33);
        } else printf("illegal notaryid.%d vs n.%d\n",kp->notaryid,n);
    }
    pthread_mutex_unlock(&safecoin_mutex);
    if ( (n < 64 && mask == ((1LL << n)-1)) || (n == 64 && mask == 0xffffffffffffffffLL) )
      //        return(n);
      //printf("error retrieving notaries ht.%d got mask.%llx for n.%d\n",height,(long long)mask,n);
    return(-1);
}

int32_t safecoin_electednotary(int32_t *numnotariesp,uint8_t *pubkey33,int32_t height,uint32_t timestamp)
{
    int32_t i,n; uint8_t pubkeys[64][33];
    n = safecoin_notaries(pubkeys,height,timestamp);
    *numnotariesp = n;
    for (i=0; i<n; i++)
    {
      if ( memcmp(pubkey33,pubkeys[i],33) == 0 )
	            return(-1);
    }
    return(-1);
}

int32_t safecoin_ratify_threshold(int32_t height,uint64_t signedmask)
{
    int32_t htind,numnotaries,i,wt = 0;
    htind = height / SAFECOIN_ELECTION_GAP;
    if ( htind >= SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP )
        htind = (SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP) - 1;
    numnotaries = Pubkeys[htind].numnotaries;
    for (i=0; i<numnotaries; i++)
        if ( ((1LL << i) & signedmask) != 0 )
            wt++;
    if ( wt > (numnotaries >> 1) || (wt > 7 && (signedmask & 1) != 0) )
             return(0);
    else return(0);
}

void safecoin_notarysinit(int32_t origheight,uint8_t pubkeys[64][33],int32_t num)
{
    static int32_t hwmheight;
    int32_t k,i,htind,height; struct knotary_entry *kp; struct knotaries_entry N;
    if ( Pubkeys == 0 )
        Pubkeys = (struct knotaries_entry *)calloc(1 + (SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP),sizeof(*Pubkeys));
    memset(&N,0,sizeof(N));
    if ( origheight > 0 )
    {
        height = (origheight + SAFECOIN_ELECTION_GAP/2);
        height /= SAFECOIN_ELECTION_GAP;
        height = ((height + 1) * SAFECOIN_ELECTION_GAP);
        htind = (height / SAFECOIN_ELECTION_GAP);
        if ( htind >= SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP )
            htind = (SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP) - 1;
        //printf("htind.%d activation %d from %d vs %d | hwmheight.%d %s\n",htind,height,origheight,(((origheight+SAFECOIN_ELECTION_GAP/2)/SAFECOIN_ELECTION_GAP)+1)*SAFECOIN_ELECTION_GAP,hwmheight,ASSETCHAINS_SYMBOL);
    } else htind = 0;
    pthread_mutex_lock(&safecoin_mutex);
    for (k=0; k<num; k++)
    {
        kp = (struct knotary_entry *)calloc(1,sizeof(*kp));
        memcpy(kp->pubkey,pubkeys[k],33);
        kp->notaryid = k;
        HASH_ADD_KEYPTR(hh,N.Notaries,kp->pubkey,33,kp);
        if ( 0 && height > 10000 )
        {
            for (i=0; i<33; i++)
                printf("%02x",pubkeys[k][i]);
            printf(" notarypubs.[%d] ht.%d active at %d\n",k,origheight,htind*SAFECOIN_ELECTION_GAP);
        }
    }
    N.numnotaries = num;
    for (i=htind; i<SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP; i++)
    {
        if ( Pubkeys[i].height != 0 && origheight < hwmheight )
        {
            printf("Pubkeys[%d].height %d < %d hwmheight, origheight.%d\n",i,Pubkeys[i].height,hwmheight,origheight);
            break;
        }
        Pubkeys[i] = N;
        Pubkeys[i].height = i * SAFECOIN_ELECTION_GAP;
    }
    pthread_mutex_unlock(&safecoin_mutex);
    if ( origheight > hwmheight )
        hwmheight = origheight;
}

int32_t safecoin_chosennotary(int32_t *notaryidp,int32_t height,uint8_t *pubkey33,uint32_t timestamp)
{
    // -1 if not notary, 0 if notary, 1 if special notary
    struct knotary_entry *kp; int32_t numnotaries=0,htind,modval = -1;
    *notaryidp = -1;
    if ( height < 0 )//|| height >= SAFECOIN_MAXBLOCKS )
    {
        printf("safecoin_chosennotary ht.%d illegal\n",height);
        return(-1);
    }
    if ( height >= SAFECOIN_NOTARIES_HARDCODED || ASSETCHAINS_SYMBOL[0] != 0 )
    {
        if ( (*notaryidp= safecoin_electednotary(&numnotaries,pubkey33,height,timestamp)) >= 0 && numnotaries != 0 )
        {
            modval = ((height % numnotaries) == *notaryidp);
            return(modval);
        }
    }
    if ( height >= 250000 )
        return(-1);
    if ( Pubkeys == 0 )
        safecoin_init(0);
    htind = height / SAFECOIN_ELECTION_GAP;
    if ( htind >= SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP )
        htind = (SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP) - 1;
    pthread_mutex_lock(&safecoin_mutex);
    HASH_FIND(hh,Pubkeys[htind].Notaries,pubkey33,33,kp);
    pthread_mutex_unlock(&safecoin_mutex);
    if ( kp != 0 )
    {
        if ( (numnotaries= Pubkeys[htind].numnotaries) > 0 )
        {
            *notaryidp = kp->notaryid;
            modval = ((height % numnotaries) == kp->notaryid);
            //printf("found notary.%d ht.%d modval.%d\n",kp->notaryid,height,modval);
        } else printf("unexpected zero notaries at height.%d\n",height);
    } //else printf("cant find kp at htind.%d ht.%d\n",htind,height);
    //int32_t i; for (i=0; i<33; i++)
    //    printf("%02x",pubkey33[i]);
    //printf(" ht.%d notary.%d special.%d htind.%d num.%d\n",height,*notaryidp,modval,htind,numnotaries);
    return(modval);
}

//struct safecoin_state *safecoin_stateptr(char *symbol,char *dest);

struct notarized_checkpoint *safecoin_npptr_for_height(int32_t height, int *idx)
{
    char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; int32_t i; struct safecoin_state *sp; struct notarized_checkpoint *np = 0;
    if ( (sp= safecoin_stateptr(symbol,dest)) != 0 )
    {
        for (i=sp->NUM_NPOINTS-1; i>=0; i--)
        {
            *idx = i;
            np = &sp->NPOINTS[i];
            if ( np->MoMdepth != 0 && height > np->notarized_height-(np->MoMdepth&0xffff) && height <= np->notarized_height )
                return(np);
        }
    }
    *idx = -1;
    return(0);
}

struct notarized_checkpoint *safecoin_npptr(int32_t height)
{
    int idx;
    return safecoin_npptr_for_height(height, &idx);
}

struct notarized_checkpoint *safecoin_npptr_at(int idx)
{
    char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; struct safecoin_state *sp;
    if ( (sp= safecoin_stateptr(symbol,dest)) != 0 )
        if (idx < sp->NUM_NPOINTS)
            return &sp->NPOINTS[idx];
    return(0);
}

int32_t safecoin_prevMoMheight()
{
    static uint256 zero;
    char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; int32_t i; struct safecoin_state *sp; struct notarized_checkpoint *np = 0;
    if ( (sp= safecoin_stateptr(symbol,dest)) != 0 )
    {
        for (i=sp->NUM_NPOINTS-1; i>=0; i--)
        {
            np = &sp->NPOINTS[i];
            if ( np->MoM != zero )
                return(np->notarized_height);
        }
    }
    return(0);
}

int32_t safecoin_notarized_height(int32_t *prevMoMheightp,uint256 *hashp,uint256 *txidp)
{
    char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; struct safecoin_state *sp;
    if ( (sp= safecoin_stateptr(symbol,dest)) != 0 )
    {
        *hashp = sp->NOTARIZED_HASH;
        *txidp = sp->NOTARIZED_DESTTXID;
        *prevMoMheightp = safecoin_prevMoMheight();
        return(sp->NOTARIZED_HEIGHT);
    }
    else
    {
        *prevMoMheightp = 0;
        memset(hashp,0,sizeof(*hashp));
        memset(txidp,0,sizeof(*txidp));
        return(0);
    }
}

int32_t safecoin_dpowconfs(int32_t txheight,int32_t numconfs)
{
    char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; struct safecoin_state *sp;
    if ( SAFECOIN_DPOWCONFS != 0 && txheight > 0 && numconfs > 0 && (sp= safecoin_stateptr(symbol,dest)) != 0 )
    {
        if ( sp->NOTARIZED_HEIGHT > 0 )
        {
            if ( txheight < sp->NOTARIZED_HEIGHT )
                return(numconfs);
            else return(1);
        }
    }
    return(numconfs);
}

int32_t safecoin_MoMdata(int32_t *notarized_htp,uint256 *MoMp,uint256 *safetxidp,int32_t height,uint256 *MoMoMp,int32_t *MoMoMoffsetp,int32_t *MoMoMdepthp,int32_t *safestartip,int32_t *safeendip)
{
    struct notarized_checkpoint *np = 0;
    if ( (np= safecoin_npptr(height)) != 0 )
    {
        *notarized_htp = np->notarized_height;
        *MoMp = np->MoM;
        *safetxidp = np->notarized_desttxid;
        *MoMoMp = np->MoMoM;
        *MoMoMoffsetp = np->MoMoMoffset;
        *MoMoMdepthp = np->MoMoMdepth;
        *safestartip = np->safestarti;
        *safeendip = np->safeendi;
        return(np->MoMdepth & 0xffff);
    }
    *notarized_htp = *MoMoMoffsetp = *MoMoMdepthp = *safestartip = *safeendip = 0;
    memset(MoMp,0,sizeof(*MoMp));
    memset(MoMoMp,0,sizeof(*MoMoMp));
    memset(safetxidp,0,sizeof(*safetxidp));
    return(0);
}

int32_t safecoin_notarizeddata(int32_t nHeight,uint256 *notarized_hashp,uint256 *notarized_desttxidp)
{
    struct notarized_checkpoint *np = 0; int32_t i=0,flag = 0; char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; struct safecoin_state *sp;
    if ( (sp= safecoin_stateptr(symbol,dest)) != 0 )
    {
        if ( sp->NUM_NPOINTS > 0 )
        {
            flag = 0;
            if ( sp->last_NPOINTSi < sp->NUM_NPOINTS && sp->last_NPOINTSi > 0 )
            {
                np = &sp->NPOINTS[sp->last_NPOINTSi-1];
                if ( np->nHeight < nHeight )
                {
                    for (i=sp->last_NPOINTSi; i<sp->NUM_NPOINTS; i++)
                    {
                        if ( sp->NPOINTS[i].nHeight >= nHeight )
                        {
                            //printf("flag.1 i.%d np->ht %d [%d].ht %d >= nHeight.%d, last.%d num.%d\n",i,np->nHeight,i,sp->NPOINTS[i].nHeight,nHeight,sp->last_NPOINTSi,sp->NUM_NPOINTS);
                            flag = 1;
                            break;
                        }
                        np = &sp->NPOINTS[i];
                        sp->last_NPOINTSi = i;
                    }
                }
            }
            if ( flag == 0 )
            {
                np = 0;
                for (i=0; i<sp->NUM_NPOINTS; i++)
                {
                    if ( sp->NPOINTS[i].nHeight >= nHeight )
                    {
                        //printf("i.%d np->ht %d [%d].ht %d >= nHeight.%d\n",i,np->nHeight,i,sp->NPOINTS[i].nHeight,nHeight);
                        break;
                    }
                    np = &sp->NPOINTS[i];
                    sp->last_NPOINTSi = i;
                }
            }
        }
        if ( np != 0 )
        {
            //char str[65],str2[65]; printf("[%s] notarized_ht.%d\n",ASSETCHAINS_SYMBOL,np->notarized_height);
            if ( np->nHeight >= nHeight || (i < sp->NUM_NPOINTS && np[1].nHeight < nHeight) )
                printf("warning: flag.%d i.%d np->ht %d [1].ht %d >= nHeight.%d\n",flag,i,np->nHeight,np[1].nHeight,nHeight);
            *notarized_hashp = np->notarized_hash;
            *notarized_desttxidp = np->notarized_desttxid;
            return(np->notarized_height);
        }
    }
    memset(notarized_hashp,0,sizeof(*notarized_hashp));
    memset(notarized_desttxidp,0,sizeof(*notarized_desttxidp));
    return(0);
}

void safecoin_notarized_update(struct safecoin_state *sp,int32_t nHeight,int32_t notarized_height,uint256 notarized_hash,uint256 notarized_desttxid,uint256 MoM,int32_t MoMdepth)
{
    struct notarized_checkpoint *np;
    if ( notarized_height >= nHeight )
    {
        fprintf(stderr,"safecoin_notarized_update REJECT notarized_height %d > %d nHeight\n",notarized_height,nHeight);
        return;
    }
    if ( 0 && ASSETCHAINS_SYMBOL[0] != 0 )
        fprintf(stderr,"[%s] safecoin_notarized_update nHeight.%d notarized_height.%d\n",ASSETCHAINS_SYMBOL,nHeight,notarized_height);
    portable_mutex_lock(&safecoin_mutex);
    sp->NPOINTS = (struct notarized_checkpoint *)realloc(sp->NPOINTS,(sp->NUM_NPOINTS+1) * sizeof(*sp->NPOINTS));
    np = &sp->NPOINTS[sp->NUM_NPOINTS++];
    memset(np,0,sizeof(*np));
    np->nHeight = nHeight;
    sp->NOTARIZED_HEIGHT = np->notarized_height = notarized_height;
    sp->NOTARIZED_HASH = np->notarized_hash = notarized_hash;
    sp->NOTARIZED_DESTTXID = np->notarized_desttxid = notarized_desttxid;
    sp->MoM = np->MoM = MoM;
    sp->MoMdepth = np->MoMdepth = MoMdepth;
    portable_mutex_unlock(&safecoin_mutex);
}

void safecoin_init(int32_t height)
{
    static int didinit; uint256 zero; int32_t k,n; uint8_t pubkeys[64][33];
    if ( 0 && height != 0 )
        printf("safecoin_init ht.%d didinit.%d\n",height,didinit);
    memset(&zero,0,sizeof(zero));
    if ( didinit == 0 )
    {
        pthread_mutex_init(&safecoin_mutex,NULL);
        decode_hex(NOTARY_PUBKEY33,33,(char *)NOTARY_PUBKEY.c_str());
        if ( height >= 0 )
        {
            n = (int32_t)(sizeof(Notaries_genesis)/sizeof(*Notaries_genesis));
            for (k=0; k<n; k++)
            {
                if ( Notaries_genesis[k][0] == 0 || Notaries_genesis[k][1] == 0 || Notaries_genesis[k][0][0] == 0 || Notaries_genesis[k][1][0] == 0 )
                    break;
                decode_hex(pubkeys[k],33,(char *)Notaries_genesis[k][1]);
            }
            safecoin_notarysinit(0,pubkeys,k);
        }
        //for (i=0; i<sizeof(Minerids); i++)
        //    Minerids[i] = -2;
        didinit = 1;
        safecoin_stateupdate(0,0,0,0,zero,0,0,0,0,0,0,0,0,0,0,zero,0);
    }
}
