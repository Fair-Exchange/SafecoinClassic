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

#ifndef H_SAFECOINCCDATA_H
#define H_SAFECOINCCDATA_H

struct safecoin_ccdata *CC_data;
int32_t CC_firstheight;

uint256 BuildMerkleTree(bool* fMutated, const std::vector<uint256> leaves, std::vector<uint256> &vMerkleTree);

uint256 safecoin_calcMoM(int32_t height,int32_t MoMdepth)
{
    static uint256 zero; CBlockIndex *pindex; int32_t i; std::vector<uint256> tree, leaves;
    bool fMutated;
    MoMdepth &= 0xffff;  // In case it includes the ccid
    if ( MoMdepth >= height )
        return zero;
    for (i=0; i<MoMdepth; i++)
    {
        if ( (pindex= safecoin_chainactive(height - i)) == nullptr )
            return zero;
        leaves.push_back(pindex->hashMerkleRoot);
    }
    return BuildMerkleTree(&fMutated, leaves, tree);
}

struct safecoin_ccdata_entry *safecoin_allMoMs(int32_t *nump,uint256 *MoMoMp,int32_t safestarti,int32_t safeendi)
{
    struct safecoin_ccdata_entry *allMoMs=0; struct safecoin_ccdata *ccdata,*tmpptr; int32_t i,num,max;
    bool fMutated; std::vector<uint256> tree, leaves;
    num = max = 0;
    portable_mutex_lock(&SAFECOIN_CC_mutex);
    DL_FOREACH_SAFE(CC_data,ccdata,tmpptr)
    {
        if ( ccdata->MoMdata.height <= safeendi && ccdata->MoMdata.height >= safestarti )
        {
            if ( num >= max )
            {
                max += 100;
                allMoMs = (struct safecoin_ccdata_entry *)realloc(allMoMs,max * sizeof(*allMoMs));
            }
            allMoMs[num].MoM = ccdata->MoMdata.MoM;
            allMoMs[num].notarized_height = ccdata->MoMdata.notarized_height;
            allMoMs[num].safeheight = ccdata->MoMdata.height;
            allMoMs[num].txi = ccdata->MoMdata.txi;
            strcpy(allMoMs[num++].symbol,ccdata->symbol);
        }
        if ( ccdata->MoMdata.height < safestarti )
            break;
    }
    portable_mutex_unlock(&SAFECOIN_CC_mutex);
    if ( (*nump= num) > 0 )
    {
        for (i=0; i<num; i++)
            leaves.push_back(allMoMs[i].MoM);
        *MoMoMp = BuildMerkleTree(&fMutated, leaves, tree);
    }
    else
    {
        free(allMoMs);
        allMoMs = nullptr;
    }
    return allMoMs;
}

int32_t safecoin_addpair(struct safecoin_ccdataMoMoM *mdata,int32_t notarized_height,int32_t offset,int32_t maxpairs)
{
    if ( maxpairs < 0) {
        fprintf(stderr,"safecoin_addpair.maxpairs %d must be >= 0\n",(int32_t)maxpairs);
        return -1;
    }
    if ( mdata->numpairs >= maxpairs )
    {
        maxpairs += 100;
        mdata->pairs = (struct safecoin_ccdatapair *)realloc(mdata->pairs,sizeof(*mdata->pairs)*maxpairs);
        //fprintf(stderr,"pairs reallocated to %p num.%d\n",mdata->pairs,mdata->numpairs);
    }
    mdata->pairs[mdata->numpairs].notarized_height = notarized_height;
    mdata->pairs[mdata->numpairs].MoMoMoffset = offset;
    mdata->numpairs++;
    return maxpairs;
}

int8_t safecoin_MoMoMdata(char *hexstr,int32_t hexsize,struct safecoin_ccdataMoMoM *mdata,char *symbol,int32_t safeheight,int32_t notarized_height)
{
    uint8_t hexdata[8192]; struct safecoin_ccdata *ccdata,*tmpptr; int32_t len,maxpairs,i,retval=-1,depth,starti,endi,CCid=0; struct safecoin_ccdata_entry *allMoMs;
    starti = endi = depth = len = maxpairs = 0;
    hexstr[0] = '\0';
    if ( sizeof(hexdata)*2+1 > hexsize )
    {
        fprintf(stderr,"hexsize.%d too small for %d\n",hexsize,(int32_t)sizeof(hexdata));
        return -1;
    }
    memset(mdata,0,sizeof(*mdata));
    portable_mutex_lock(&SAFECOIN_CC_mutex);
    DL_FOREACH_SAFE(CC_data,ccdata,tmpptr)
    {
        if ( ccdata->MoMdata.height < safeheight )
        {
            //fprintf(stderr,"%s notarized.%d safe.%d\n",ccdata->symbol,ccdata->MoMdata.notarized_height,ccdata->MoMdata.height);
            if ( strcmp(ccdata->symbol,symbol) == 0 )
            {
                if ( endi == 0 )
                {
                    endi = ccdata->MoMdata.height;
                    CCid = ccdata->CCid;
                }
                if ( (mdata->numpairs == 1 && notarized_height == 0) || ccdata->MoMdata.notarized_height <= notarized_height )
                {
                    starti = ccdata->MoMdata.height + 1;
                    if ( notarized_height == 0 )
                        notarized_height = ccdata->MoMdata.notarized_height;
                    break;
                }
            }
            starti = ccdata->MoMdata.height;
        }
    }
    portable_mutex_unlock(&SAFECOIN_CC_mutex);
    mdata->safestarti = starti;
    mdata->safeendi = endi;
    if ( starti != 0 && endi != 0 && endi >= starti )
    {
        if ( (allMoMs= safecoin_allMoMs(&depth,&mdata->MoMoM,starti,endi)) != nullptr )
        {
            mdata->MoMoMdepth = depth;
            for (i=0; i<depth; i++)
            {
                if ( strcmp(symbol,allMoMs[i].symbol) == 0 )
                    maxpairs = safecoin_addpair(mdata,allMoMs[i].notarized_height,i,maxpairs);
            }
            if ( mdata->numpairs > 0 )
            {
                len += iguana_rwnum(1,&hexdata[len],sizeof(CCid),(uint8_t *)&CCid);
                len += iguana_rwnum(1,&hexdata[len],sizeof(uint32_t),(uint8_t *)&mdata->safestarti);
                len += iguana_rwnum(1,&hexdata[len],sizeof(uint32_t),(uint8_t *)&mdata->safeendi);
                len += iguana_rwbignum(1,&hexdata[len],sizeof(mdata->MoMoM),(uint8_t *)&mdata->MoMoM);
                len += iguana_rwnum(1,&hexdata[len],sizeof(uint32_t),(uint8_t *)&mdata->MoMoMdepth);
                len += iguana_rwnum(1,&hexdata[len],sizeof(uint32_t),(uint8_t *)&mdata->numpairs);
                for (i=0; i<mdata->numpairs; i++)
                {
                    if ( len + sizeof(uint32_t)*2 > sizeof(hexdata) )
                    {
                        fprintf(stderr,"%s %d %d i.%d of %d exceeds hexdata.%d\n",symbol,safeheight,notarized_height,i,mdata->numpairs,(int32_t)sizeof(hexdata));
                        break;
                    }
                    len += iguana_rwnum(1,&hexdata[len],sizeof(uint32_t),(uint8_t *)&mdata->pairs[i].notarized_height);
                    len += iguana_rwnum(1,&hexdata[len],sizeof(uint32_t),(uint8_t *)&mdata->pairs[i].MoMoMoffset);
                }
                if ( i == mdata->numpairs && len*2+1 < hexsize )
                {
                    init_hexbytes_noT(hexstr,hexdata,len);
                    //fprintf(stderr,"hexstr.(%s)\n",hexstr);
                    retval = 0;
                } else fprintf(stderr,"%s %d %d too much hexdata[%d] for hexstr[%d]\n",symbol,safeheight,notarized_height,len,hexsize);
            }
            free(allMoMs);
        }
    }
    return retval;
}

void safecoin_purge_ccdata(int32_t height)
{
    struct safecoin_ccdata *ccdata,*tmpptr;
    if ( ASSETCHAINS_SYMBOL[0] == '\0' )
    {
        portable_mutex_lock(&SAFECOIN_CC_mutex);
        DL_FOREACH_SAFE(CC_data,ccdata,tmpptr)
        {
            if ( ccdata->MoMdata.height < height )
                break;
            printf("PURGE %s notarized.%d\n",ccdata->symbol,ccdata->MoMdata.notarized_height);
            DL_DELETE(CC_data,ccdata);
            free(ccdata);
        }
        portable_mutex_unlock(&SAFECOIN_CC_mutex);
    }
    // else
    // {
    //     // purge notarized data
    // }
}

// this is just a demo of ccdata processing to create example data for the MoMoM and allMoMs calls
bool safecoin_rwccdata(char *thischain,int32_t rwflag,struct safecoin_ccdata *ccdata,struct safecoin_ccdataMoMoM *MoMoMdata)
{
    uint256 hash,zero; bits256 tmp; int32_t i,nonz; struct safecoin_ccdata *ptr; struct notarized_checkpoint *np;
    return false; // disable this path as libscott method is much better
    if ( rwflag == 0 )
    {
        // load from disk
    }
    else
    {
        // write to disk
    }
    if ( ccdata->MoMdata.height > 0 && (CC_firstheight == 0 || ccdata->MoMdata.height < CC_firstheight) )
        CC_firstheight = ccdata->MoMdata.height;
    for (nonz=i=0; i<32; i++)
    {
        if ( (tmp.bytes[i]= ((uint8_t *)&ccdata->MoMdata.MoM)[31-i]) != 0 )
            ++nonz;
    }
    if ( nonz == 0 )
        return false;
    memcpy(&hash,&tmp,sizeof(hash));
    //fprintf(stderr,"[%s] ccdata.%s id.%d notarized_ht.%d MoM.%s height.%d/t%d\n",ASSETCHAINS_SYMBOL,ccdata->symbol,ccdata->CCid,ccdata->MoMdata.notarized_height,hash.ToString().c_str(),ccdata->MoMdata.height,ccdata->MoMdata.txi);
    if ( ASSETCHAINS_SYMBOL[0] == '\0' )
    {
        if ( CC_data != nullptr && (CC_data->MoMdata.height > ccdata->MoMdata.height || (CC_data->MoMdata.height == ccdata->MoMdata.height && CC_data->MoMdata.txi >= ccdata->MoMdata.txi)) )
            printf("out of order detected? SKIP CC_data ht.%d/txi.%d vs ht.%d/txi.%d\n",CC_data->MoMdata.height,CC_data->MoMdata.txi,ccdata->MoMdata.height,ccdata->MoMdata.txi);
        else
        {
            ptr = (struct safecoin_ccdata *)calloc(1,sizeof(*ptr));
            *ptr = *ccdata;
            portable_mutex_lock(&SAFECOIN_CC_mutex);
            DL_PREPEND(CC_data,ptr);
            portable_mutex_unlock(&SAFECOIN_CC_mutex);
        }
    }
    else
    {
        if ( MoMoMdata != nullptr && MoMoMdata->pairs != nullptr )
        {
            for (i=0; i<MoMoMdata->numpairs; i++)
            {
                if ( (np= safecoin_npptr(MoMoMdata->pairs[i].notarized_height)) != nullptr )
                {
                    memset(&zero,0,sizeof(zero));
                    if ( memcmp(&np->MoMoM,&zero,sizeof(np->MoMoM)) == 0 )
                    {
                        np->MoMoM = MoMoMdata->MoMoM;
                        np->MoMoMdepth = MoMoMdata->MoMoMdepth;
                        np->MoMoMoffset = MoMoMdata->MoMoMoffset;
                        np->safestarti = MoMoMdata->safestarti;
                        np->safeendi = MoMoMdata->safeendi;
                    }
                    else if ( memcmp(&np->MoMoM,&MoMoMdata->MoMoM,sizeof(np->MoMoM)) != 0 || np->MoMoMdepth != MoMoMdata->MoMoMdepth || np->MoMoMoffset != MoMoMdata->MoMoMoffset || np->safestarti != MoMoMdata->safestarti || np->safeendi != MoMoMdata->safeendi )
                    {
                        fprintf(stderr,"preexisting MoMoM mismatch: %s (%d %d %d %d) vs %s (%d %d %d %d)\n",np->MoMoM.ToString().c_str(),np->MoMoMdepth,np->MoMoMoffset,np->safestarti,np->safeendi,MoMoMdata->MoMoM.ToString().c_str(),MoMoMdata->MoMoMdepth,MoMoMdata->MoMoMoffset,MoMoMdata->safestarti,MoMoMdata->safeendi);
                    }
                }
            }
        }
    }
    return true;
}

#endif
