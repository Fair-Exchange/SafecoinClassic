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

#define SAFECOIN_MAINNET_START 178999

const char *Notaries_genesis[][2] =
{
    {"0dev1_jj", "0333b9796526ef8de88712a649d618689a1de1ed1adf9fb5ec415f31e560b1f9a3" },
    {"0dev2_oleksandr", "03f5c47ec482fa1a57821edd0c492948aec9b22ab2b4e38e45fba34e4b6f697a29" },
    {"0dev3_arch", "0248c657bf46ff8b77c230134fc04482dd549b91d4fb2ba27414bec02edac4ae98" },
    {"0dev4_rag", "030ca5b3f0ad6eac4afd90b2be8e52a74df852960b9bb4b69bcd413ad2df6232fe" },
    {"bman_1", "02d3d47e14af1be6617c8e92dbab0537efb47f7732f5afb1024209b60a9d84a31c" },
    {"bman_2", "03608d2368b19ae3c47d9496283630953dfa85526fe1cad159d9ef8b796f3236be" },
    {"bman_3", "02448b40e1cca6367f6e10aaf00faabdcca9c219d453d67548f2e6fd08ce90c10f" },
    {"bman_4", "02e55b44a4ce698e0ee6fed3fc571e06d3939dc0537851dc23246734a2b181f1c4" },
    {"traysi_1", "0255895db02e46d65c6ad6313a467074949efa47feefc003b1d96ec309151c4340" },
    {"traysi_2", "0221fa83d4c5f04c63b9bb3a7085242e8daa83c9a97024a4f46720dd174ed1764a" },
    {"safenode_a", "031e332d04f067aad39553330d3dbb99deaaa97fac579e5633b6483abe3f503654" }, // 10
    {"safenode_b", "03f19b118737f54a586dd33e92dbb397fc29c88413b41ac21b87440bec58070ef9" },
    {"safenode_c", "02d72b424eee08eb333a9c95d8915bba4e5e05b9a42080eb6811907b73ea30b474" },
    {"safenode_d", "020cc2dd8eea9955f66eb127236763dd057a845d8f830c5357d90705f9d23797a6" },
    {"safenode_d", "025f1dde907090870289ee8f8ef7a870473c00080d344365efda5a23c4c305f93a" },
    {"safenode_e", "0328ac56b5835d03774724fadee4d1b09cea956515e57cbe95d599e6dd0caced4b" },
    {"safenode_f", "03433e564ba7287dce6883e9bc73354654e6d305204bcb1fab4bf1e42675eb4c2f" },
    {"safenode_g", "02c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9" },
    {"safenode_h", "0318cf394b58e9b56ddd62fb03082e5382575a60e440a23fbb7380e7fd50b295eb" },
    {"safenode_i", "026676e7fa71ca8fd6436bb2a218500e82411d942e2f3dd46bbf31985654a569ed" },
    {"safenode_j", "02aa030a8bd00c430d2846ebad41af3ff12d5a4507ec12dcb3de485e2aa6bfd0a1" }, // 20
    {"safenode_k", "036fd60dcac267a26771093df5210511e0317031263d66ddf8d104813a3159d18d" },
    {"safenode_l", "02d300502f61150d580a42a09963e347a2ad3ce51f11960d358df8f394f9672a67" },
    {"safenode_m", "02412d9dd21f2457cba8533e08679898a2ffa48fe4c4691e2a696842749c80031f" },
    {"safenode_n", "0277b12ff3cd22325fde276e706d365b2757d5e27f3c23005dece66ebb0c58a0fe" },
    {"safenode_o", "0213671eba7c4c03e07629bc30b071571605a478f65b1dfff2343e5275b6974d7c" },
    {"safenode_p", "025bedc84e35a3bb89c3126656ad83854573928030bb313472e3a13cc52b2f8cf2" },
    {"safenode_q", "03f5c5dec766e84ac5a378650ed82ea0df459a0022d9f7a85e7f94426d01c7f128" },
    {"safenode_r", "0357a41230ffd72d1fd9379500ac97ac27d0b0a0a6e4197ba4d1f76ff4f88ff1e2" },
    {"safenode_s", "02380c684558673aa7cdc638fd8b2ca8f2b7ae5b7d15a622b10b2b406f43c7f1cc" },
    {"safenode_t", "02d8ddaa4d3dbb38cb1e3fd769f05efc8985243f414a045889be9ec5ad688a1dce" }, // 30
    {"safenode_u", "039846a7ae3bee6390ef7ee95769a7443aa1bb5d7e85afd676ebe7ad7420010135" },
};

const char *Notaries_elected0[][2] =
{
    {"0dev1_jj", "0333b9796526ef8de88712a649d618689a1de1ed1adf9fb5ec415f31e560b1f9a3" },
    {"0dev2_oleksandr", "03f5c47ec482fa1a57821edd0c492948aec9b22ab2b4e38e45fba34e4b6f697a29" },
    {"0dev3_arch", "0248c657bf46ff8b77c230134fc04482dd549b91d4fb2ba27414bec02edac4ae98" },
    {"0dev4_rag", "030ca5b3f0ad6eac4afd90b2be8e52a74df852960b9bb4b69bcd413ad2df6232fe" },
    {"bman_1", "02d3d47e14af1be6617c8e92dbab0537efb47f7732f5afb1024209b60a9d84a31c" },
    {"bman_2", "03608d2368b19ae3c47d9496283630953dfa85526fe1cad159d9ef8b796f3236be" },
    {"bman_3", "02448b40e1cca6367f6e10aaf00faabdcca9c219d453d67548f2e6fd08ce90c10f" },
    {"bman_4", "02e55b44a4ce698e0ee6fed3fc571e06d3939dc0537851dc23246734a2b181f1c4" },
    {"traysi_1", "0255895db02e46d65c6ad6313a467074949efa47feefc003b1d96ec309151c4340" },
    {"traysi_2", "0221fa83d4c5f04c63b9bb3a7085242e8daa83c9a97024a4f46720dd174ed1764a" },
    {"safenode_a", "031e332d04f067aad39553330d3dbb99deaaa97fac579e5633b6483abe3f503654" }, // 10
    {"safenode_b", "03f19b118737f54a586dd33e92dbb397fc29c88413b41ac21b87440bec58070ef9" },
    {"safenode_c", "02d72b424eee08eb333a9c95d8915bba4e5e05b9a42080eb6811907b73ea30b474" },
    {"safenode_d", "020cc2dd8eea9955f66eb127236763dd057a845d8f830c5357d90705f9d23797a6" },
    {"safenode_d", "025f1dde907090870289ee8f8ef7a870473c00080d344365efda5a23c4c305f93a" },
    {"safenode_e", "0328ac56b5835d03774724fadee4d1b09cea956515e57cbe95d599e6dd0caced4b" },
    {"safenode_f", "03433e564ba7287dce6883e9bc73354654e6d305204bcb1fab4bf1e42675eb4c2f" },
    {"safenode_g", "02c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9" },
    {"safenode_h", "0318cf394b58e9b56ddd62fb03082e5382575a60e440a23fbb7380e7fd50b295eb" },
    {"safenode_i", "026676e7fa71ca8fd6436bb2a218500e82411d942e2f3dd46bbf31985654a569ed" },
    {"safenode_j", "02aa030a8bd00c430d2846ebad41af3ff12d5a4507ec12dcb3de485e2aa6bfd0a1" }, // 20
    {"safenode_k", "036fd60dcac267a26771093df5210511e0317031263d66ddf8d104813a3159d18d" },
    {"safenode_l", "02d300502f61150d580a42a09963e347a2ad3ce51f11960d358df8f394f9672a67" },
    {"safenode_m", "02412d9dd21f2457cba8533e08679898a2ffa48fe4c4691e2a696842749c80031f" },
    {"safenode_n", "0277b12ff3cd22325fde276e706d365b2757d5e27f3c23005dece66ebb0c58a0fe" },
    {"safenode_o", "0213671eba7c4c03e07629bc30b071571605a478f65b1dfff2343e5275b6974d7c" },
    {"safenode_p", "025bedc84e35a3bb89c3126656ad83854573928030bb313472e3a13cc52b2f8cf2" },
    {"safenode_q", "03f5c5dec766e84ac5a378650ed82ea0df459a0022d9f7a85e7f94426d01c7f128" },
    {"safenode_r", "0357a41230ffd72d1fd9379500ac97ac27d0b0a0a6e4197ba4d1f76ff4f88ff1e2" },
    {"safenode_s", "02380c684558673aa7cdc638fd8b2ca8f2b7ae5b7d15a622b10b2b406f43c7f1cc" },
    {"safenode_t", "02d8ddaa4d3dbb38cb1e3fd769f05efc8985243f414a045889be9ec5ad688a1dce" }, // 30
    {"safenode_u", "039846a7ae3bee6390ef7ee95769a7443aa1bb5d7e85afd676ebe7ad7420010135" },
};

#define SAFECOIN_NOTARIES_TIMESTAMP1 1525132800 // May 1st 2018 1530921600 // 7/7/2017
#define SAFECOIN_NOTARIES_HEIGHT1 ((513000 / SAFECOIN_ELECTION_GAP) * SAFECOIN_ELECTION_GAP)

const char *Notaries_elected1[][2] =
{
    {"0dev1_jj", "0333b9796526ef8de88712a649d618689a1de1ed1adf9fb5ec415f31e560b1f9a3" },
    {"0dev2_oleksandr", "03f5c47ec482fa1a57821edd0c492948aec9b22ab2b4e38e45fba34e4b6f697a29" },
    {"0dev3_arch", "0248c657bf46ff8b77c230134fc04482dd549b91d4fb2ba27414bec02edac4ae98" },
    {"0dev4_rag", "030ca5b3f0ad6eac4afd90b2be8e52a74df852960b9bb4b69bcd413ad2df6232fe" },
    {"bman_1", "02d3d47e14af1be6617c8e92dbab0537efb47f7732f5afb1024209b60a9d84a31c" },
    {"bman_2", "03608d2368b19ae3c47d9496283630953dfa85526fe1cad159d9ef8b796f3236be" },
    {"bman_3", "02448b40e1cca6367f6e10aaf00faabdcca9c219d453d67548f2e6fd08ce90c10f" },
    {"bman_4", "02e55b44a4ce698e0ee6fed3fc571e06d3939dc0537851dc23246734a2b181f1c4" },
    {"traysi_1", "0255895db02e46d65c6ad6313a467074949efa47feefc003b1d96ec309151c4340" },
    {"traysi_2", "0221fa83d4c5f04c63b9bb3a7085242e8daa83c9a97024a4f46720dd174ed1764a" },
    {"safenode_a", "031e332d04f067aad39553330d3dbb99deaaa97fac579e5633b6483abe3f503654" }, // 10
    {"safenode_b", "03f19b118737f54a586dd33e92dbb397fc29c88413b41ac21b87440bec58070ef9" },
    {"safenode_c", "02d72b424eee08eb333a9c95d8915bba4e5e05b9a42080eb6811907b73ea30b474" },
    {"safenode_d", "020cc2dd8eea9955f66eb127236763dd057a845d8f830c5357d90705f9d23797a6" },
    {"safenode_d", "025f1dde907090870289ee8f8ef7a870473c00080d344365efda5a23c4c305f93a" },
    {"safenode_e", "0328ac56b5835d03774724fadee4d1b09cea956515e57cbe95d599e6dd0caced4b" },
    {"safenode_f", "03433e564ba7287dce6883e9bc73354654e6d305204bcb1fab4bf1e42675eb4c2f" },
    {"safenode_g", "02c8431929d7493a7feb0e397c88a6a1651f1709cb2b420b55e7d732ebc31041e9" },
    {"safenode_h", "0318cf394b58e9b56ddd62fb03082e5382575a60e440a23fbb7380e7fd50b295eb" },
    {"safenode_i", "026676e7fa71ca8fd6436bb2a218500e82411d942e2f3dd46bbf31985654a569ed" },
    {"safenode_j", "02aa030a8bd00c430d2846ebad41af3ff12d5a4507ec12dcb3de485e2aa6bfd0a1" }, // 20
    {"safenode_k", "036fd60dcac267a26771093df5210511e0317031263d66ddf8d104813a3159d18d" },
    {"safenode_l", "02d300502f61150d580a42a09963e347a2ad3ce51f11960d358df8f394f9672a67" },
    {"safenode_m", "02412d9dd21f2457cba8533e08679898a2ffa48fe4c4691e2a696842749c80031f" },
    {"safenode_n", "0277b12ff3cd22325fde276e706d365b2757d5e27f3c23005dece66ebb0c58a0fe" },
    {"safenode_o", "0213671eba7c4c03e07629bc30b071571605a478f65b1dfff2343e5275b6974d7c" },
    {"safenode_p", "025bedc84e35a3bb89c3126656ad83854573928030bb313472e3a13cc52b2f8cf2" },
    {"safenode_q", "03f5c5dec766e84ac5a378650ed82ea0df459a0022d9f7a85e7f94426d01c7f128" },
    {"safenode_r", "0357a41230ffd72d1fd9379500ac97ac27d0b0a0a6e4197ba4d1f76ff4f88ff1e2" },
    {"safenode_s", "02380c684558673aa7cdc638fd8b2ca8f2b7ae5b7d15a622b10b2b406f43c7f1cc" },
    {"safenode_t", "02d8ddaa4d3dbb38cb1e3fd769f05efc8985243f414a045889be9ec5ad688a1dce" }, // 30
    {"safenode_u", "039846a7ae3bee6390ef7ee95769a7443aa1bb5d7e85afd676ebe7ad7420010135" },
};
#define CRYPTO777_PUBSECPSTR "02004a23684b6e12441ac4c913775f4f74584c48a9167d2fb65da6a2ddc9852761"

int32_t safecoin_notaries(uint8_t pubkeys[64][33],int32_t height,uint32_t timestamp)
{
    static uint8_t elected_pubkeys0[64][33],elected_pubkeys1[64][33]; bool did0,did1; static int32_t n0,n1;
    int32_t i,htind,n; uint64_t mask = 0; struct knotary_entry *kp,*tmp;
    if ( timestamp == 0 && ASSETCHAINS_SYMBOL[0] != '\0' )
        timestamp = safecoin_heightstamp(height);
    else if ( ASSETCHAINS_SYMBOL[0] == '\0' )
        timestamp = 0;
    if ( height >= SAFECOIN_NOTARIES_HARDCODED || ASSETCHAINS_SYMBOL[0] != '\0' )
    {
        if ( (timestamp != 0 && timestamp <= SAFECOIN_NOTARIES_TIMESTAMP1) || (ASSETCHAINS_SYMBOL[0] == '\0' && height <= SAFECOIN_NOTARIES_HEIGHT1) )
        {
            if ( !did0 )
            {
                n0 = sizeof(Notaries_elected0)/sizeof(*Notaries_elected0);
                for (i=0; i<n0; i++)
                    decode_hex(elected_pubkeys0[i],33,(char *)Notaries_elected0[i][1]);
                did0 = true;
            }
            memcpy(pubkeys,elected_pubkeys0,n0 * 33);
            //if ( ASSETCHAINS_SYMBOL[0] != '\0' )
            //fprintf(stderr,"%s height.%d t.%u elected.%d notaries\n",ASSETCHAINS_SYMBOL,height,timestamp,n0);
            return n0;
        }
        //if ( (timestamp != 0 && timestamp <= SAFECOIN_NOTARIES_TIMESTAMP2) || height <= SAFECOIN_NOTARIES_HEIGHT2 )
        if ( !did1 )
        {
            n1 = sizeof(Notaries_elected1)/sizeof(*Notaries_elected1);
            for (i=0; i<n1; i++)
                decode_hex(elected_pubkeys1[i],33,(char *)Notaries_elected1[i][1]);
            if ( 0 && ASSETCHAINS_SYMBOL[0] != '\0' )
                fprintf(stderr,"%s height.%d t.%u elected.%d notaries2\n",ASSETCHAINS_SYMBOL,height,timestamp,n1);
            did1 = true;
        }
        memcpy(pubkeys,elected_pubkeys1,n1 * 33);
        return n1;
    }
    htind = height / SAFECOIN_ELECTION_GAP;
    if ( htind >= SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP )
        htind = SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP - 1;
    if ( Pubkeys == 0 )
    {
        safecoin_init(height);
        //printf("Pubkeys.%p htind.%d vs max.%d\n",Pubkeys,htind,SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP);
    }
    pthread_mutex_lock(&safecoin_mutex);
    n = Pubkeys[htind].numnotaries;
    if ( 0 && ASSETCHAINS_SYMBOL[0] != '\0' )
        fprintf(stderr,"%s height.%d t.%u genesis.%d\n",ASSETCHAINS_SYMBOL,height,timestamp,n);
    HASH_ITER(hh,Pubkeys[htind].Notaries,kp,tmp)
    {
        if ( kp->notaryid < n )
        {
            mask |= 1LL << kp->notaryid;
            memcpy(pubkeys[kp->notaryid],kp->pubkey,33);
        } else printf("illegal notaryid.%d vs n.%d\n",kp->notaryid,n);
    }
    pthread_mutex_unlock(&safecoin_mutex);
    if ( (n < 64 && mask == ((1LL << n)-1)) || (n == 64 && mask == 0xffffffffffffffffLL) )
        return n;
    printf("error retrieving notaries ht.%d got mask.%llx for n.%d\n",height,(long long)mask,n);
    return -1;
}

int32_t safecoin_electednotary(int32_t *numnotariesp,uint8_t *pubkey33,int32_t height,uint32_t timestamp)
{
    int32_t i,n; uint8_t pubkeys[64][33];
    n = safecoin_notaries(pubkeys,height,timestamp);
    *numnotariesp = n;
    for (i=0; i<n; i++)
        if ( memcmp(pubkey33,pubkeys[i],33) == 0 )
            return i;
    return -1;
}

bool safecoin_ratify_threshold(int32_t height,uint64_t signedmask)
{
    int32_t htind,numnotaries,i,wt = 0;
    htind = height / SAFECOIN_ELECTION_GAP;
    if ( htind >= SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP )
        htind = SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP - 1;
    numnotaries = Pubkeys[htind].numnotaries;
    for (i=0; i<numnotaries; i++)
        if ( (1LL << i) & signedmask != 0 )
            ++wt;
    return wt > numnotaries >> 1 || (wt > 7 && signedmask & 1 != 0);
}

void safecoin_notarysinit(int32_t origheight,uint8_t pubkeys[64][33],int32_t num)
{
    static int32_t hwmheight;
    int32_t k,i,htind=0,height; struct knotary_entry *kp; struct knotaries_entry N;
    if ( Pubkeys == nullptr )
        Pubkeys = (struct knotaries_entry *)calloc(1 + SAFECOIN_MAXBLOCKS/SAFECOIN_ELECTION_GAP,sizeof(*Pubkeys));
    memset(&N,0,sizeof(N));
    if ( origheight > 0 )
    {
        height = origheight + SAFECOIN_ELECTION_GAP/2;
        height /= SAFECOIN_ELECTION_GAP;
        height = (height + 1) * SAFECOIN_ELECTION_GAP;
        htind = height / SAFECOIN_ELECTION_GAP;
        if ( htind >= SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP )
            htind = SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP - 1;
        //printf("htind.%d activation %d from %d vs %d | hwmheight.%d %s\n",htind,height,origheight,(((origheight+SAFECOIN_ELECTION_GAP/2)/SAFECOIN_ELECTION_GAP)+1)*SAFECOIN_ELECTION_GAP,hwmheight,ASSETCHAINS_SYMBOL);
    }
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

int8_t safecoin_chosennotary(int32_t *notaryidp,int32_t height,uint8_t *pubkey33,uint32_t timestamp)
{
    // -1 if not notary, 0 if notary, 1 if special notary
    struct knotary_entry *kp; int32_t numnotaries=0,htind,modval = -1;
    *notaryidp = -1;
    if ( height < 0 )//|| height >= SAFECOIN_MAXBLOCKS )
    {
        printf("safecoin_chosennotary ht.%d illegal\n",height);
        return -1;
    }
    if ( height >= SAFECOIN_NOTARIES_HARDCODED || ASSETCHAINS_SYMBOL[0] != '\0' )
    {
        if ( (*notaryidp= safecoin_electednotary(&numnotaries,pubkey33,height,timestamp)) >= 0 && numnotaries != 0 )
        {
            modval = height % numnotaries == *notaryidp;
            return modval;
        }
    }
    if ( height >= 250000 )
        return -1;
    if ( Pubkeys == nullptr )
        safecoin_init(0);
    htind = height / SAFECOIN_ELECTION_GAP;
    if ( htind >= SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP )
        htind = (SAFECOIN_MAXBLOCKS / SAFECOIN_ELECTION_GAP) - 1;
    pthread_mutex_lock(&safecoin_mutex);
    HASH_FIND(hh,Pubkeys[htind].Notaries,pubkey33,33,kp);
    pthread_mutex_unlock(&safecoin_mutex);
    if ( kp != nullptr )
    {
        if ( (numnotaries= Pubkeys[htind].numnotaries) > 0 )
        {
            *notaryidp = kp->notaryid;
            modval = height % numnotaries == kp->notaryid;
            //printf("found notary.%d ht.%d modval.%d\n",kp->notaryid,height,modval);
        } else printf("unexpected zero notaries at height.%d\n",height);
    } //else printf("cant find kp at htind.%d ht.%d\n",htind,height);
    //int32_t i; for (i=0; i<33; i++)
    //    printf("%02x",pubkey33[i]);
    //printf(" ht.%d notary.%d special.%d htind.%d num.%d\n",height,*notaryidp,modval,htind,numnotaries);
    return modval;
}

//struct safecoin_state *safecoin_stateptr(char *symbol,char *dest);

struct notarized_checkpoint *safecoin_npptr_for_height(int32_t height, int *idx)
{
    char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; int32_t i; struct safecoin_state *sp; struct notarized_checkpoint *np = 0;
    if ( (sp= safecoin_stateptr(symbol,dest)) != 0 )
    {
        for (i=sp->NUM_NPOINTS-1; i>=0; i--)
        {
            if (idx != nullptr)
                *idx = i;
            np = &sp->NPOINTS[i];
            if ( np->MoMdepth != 0 && height > np->notarized_height-(np->MoMdepth&0xffff) && height <= np->notarized_height )
                return np;
        }
    }
    if (idx != nullptr)
        *idx = -1;
    return nullptr;
}

struct notarized_checkpoint *safecoin_npptr(int32_t height)
{
    return safecoin_npptr_for_height(height, nullptr);
}

struct notarized_checkpoint *safecoin_npptr_at(int idx)
{
    char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; struct safecoin_state *sp;
    if ( (sp= safecoin_stateptr(symbol,dest)) != nullptr )
        if (idx < sp->NUM_NPOINTS)
            return &sp->NPOINTS[idx];
    return nullptr;
}

int32_t safecoin_prevMoMheight()
{
    static uint256 zero;
    char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; int32_t i; struct safecoin_state *sp; struct notarized_checkpoint *np;
    if ( (sp= safecoin_stateptr(symbol,dest)) != nullptr )
    {
        for (i=sp->NUM_NPOINTS-1; i>=0; i--)
        {
            np = &sp->NPOINTS[i];
            if ( np->MoM != zero )
                return np->notarized_height;
        }
    }
    return 0;
}

int32_t safecoin_notarized_height(int32_t *prevMoMheightp,uint256 *hashp,uint256 *txidp)
{
    char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; struct safecoin_state *sp;
    if ( (sp= safecoin_stateptr(symbol,dest)) != nullptr )
    {
        *hashp = sp->NOTARIZED_HASH;
        *txidp = sp->NOTARIZED_DESTTXID;
        *prevMoMheightp = safecoin_prevMoMheight();
        return sp->NOTARIZED_HEIGHT;
    }
    *prevMoMheightp = 0;
    memset(hashp,0,sizeof(*hashp));
    memset(txidp,0,sizeof(*txidp));
    return 0;
}

int32_t safecoin_dpowconfs(int32_t txheight,int32_t numconfs)
{
    char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; struct safecoin_state *sp;
    if ( SAFECOIN_DPOWCONFS != 0 && txheight > 0 && numconfs > 0 && (sp= safecoin_stateptr(symbol,dest)) != nullptr && sp->NOTARIZED_HEIGHT > 0 )
    {
        if ( txheight < sp->NOTARIZED_HEIGHT )
            return numconfs;
        return 1;
    }
    return numconfs;
}

int32_t safecoin_MoMdata(int32_t *notarized_htp,uint256 *MoMp,uint256 *safetxidp,int32_t height,uint256 *MoMoMp,int32_t *MoMoMoffsetp,int32_t *MoMoMdepthp,int32_t *safestartip,int32_t *safeendip)
{
    struct notarized_checkpoint *np;
    if ( (np= safecoin_npptr(height)) != nullptr )
    {
        *notarized_htp = np->notarized_height;
        *MoMp = np->MoM;
        *safetxidp = np->notarized_desttxid;
        *MoMoMp = np->MoMoM;
        *MoMoMoffsetp = np->MoMoMoffset;
        *MoMoMdepthp = np->MoMoMdepth;
        *safestartip = np->safestarti;
        *safeendip = np->safeendi;
        return np->MoMdepth & 0xffff;
    }
    *notarized_htp = *MoMoMoffsetp = *MoMoMdepthp = *safestartip = *safeendip = 0;
    memset(MoMp,0,sizeof(*MoMp));
    memset(MoMoMp,0,sizeof(*MoMoMp));
    memset(safetxidp,0,sizeof(*safetxidp));
    return 0;
}

int32_t safecoin_notarizeddata(int32_t nHeight,uint256 *notarized_hashp,uint256 *notarized_desttxidp)
{
    struct notarized_checkpoint *np = nullptr; int32_t i=0; bool flag; char symbol[SAFECOIN_ASSETCHAIN_MAXLEN],dest[SAFECOIN_ASSETCHAIN_MAXLEN]; struct safecoin_state *sp;
    if ( (sp= safecoin_stateptr(symbol,dest)) != nullptr )
    {
        if ( sp->NUM_NPOINTS > 0 )
        {
            flag = false;
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
                            flag = true;
                            break;
                        }
                        np = &sp->NPOINTS[i];
                        sp->last_NPOINTSi = i;
                    }
                }
            }
            if ( !flag )
            {
                np = nullptr;
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
        if ( np != nullptr )
        {
            //char str[65],str2[65]; printf("[%s] notarized_ht.%d\n",ASSETCHAINS_SYMBOL,np->notarized_height);
            if ( np->nHeight >= nHeight || (i < sp->NUM_NPOINTS && np[1].nHeight < nHeight) )
                printf("warning: flag.%d i.%d np->ht %d [1].ht %d >= nHeight.%d\n",flag,i,np->nHeight,np[1].nHeight,nHeight);
            *notarized_hashp = np->notarized_hash;
            *notarized_desttxidp = np->notarized_desttxid;
            return np->notarized_height;
        }
    }
    memset(notarized_hashp,0,sizeof(*notarized_hashp));
    memset(notarized_desttxidp,0,sizeof(*notarized_desttxidp));
    return 0;
}

void safecoin_notarized_update(struct safecoin_state *sp,int32_t nHeight,int32_t notarized_height,uint256 notarized_hash,uint256 notarized_desttxid,uint256 MoM,int32_t MoMdepth)
{
    struct notarized_checkpoint *np;
    if ( notarized_height >= nHeight )
    {
        fprintf(stderr,"safecoin_notarized_update REJECT notarized_height %d > %d nHeight\n",notarized_height,nHeight);
        return;
    }
    if ( 0 && ASSETCHAINS_SYMBOL[0] != '\0' )
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
    static bool didinit; uint256 zero; int32_t k,n; uint8_t pubkeys[64][33];
    if ( 0 && height != 0 )
        printf("safecoin_init ht.%d didinit.%d\n",height,didinit);
    memset(&zero,0,sizeof(zero));
    if ( !didinit )
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
        didinit = true;
        safecoin_stateupdate(0,nullptr,0,0,zero,0,0,0,0,0,0,0,nullptr,0,0,zero,0);
    }
}
