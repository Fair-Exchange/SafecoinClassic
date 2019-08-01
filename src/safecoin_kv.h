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

#ifndef H_SAFECOINKV_H
#define H_SAFECOINKV_H

#include "safecoin_defs.h"

extern std::vector<std::string> vs_safecoin_notaries(int32_t height, uint32_t timestamp);

int32_t safecoin_kvcmp(uint8_t *refvalue,uint16_t refvaluesize,uint8_t *value,uint16_t valuesize)
{
    if ( refvalue == 0 && value == 0 )
        return(0);
    else if ( refvalue == 0 || value == 0 )
        return(-1);
    else if ( refvaluesize != valuesize )
        return(-1);
    else return(memcmp(refvalue,value,valuesize));
}

int32_t safecoin_kvnumdays(uint32_t flags)
{
    int32_t numdays;
    if ( (numdays= ((flags>>2)&0x3ff)+1) > 365 )
        numdays = 365;
    return(numdays);
}

int32_t safecoin_kvduration(uint32_t flags)
{
    return(safecoin_kvnumdays(flags) * SAFECOIN_KVDURATION);
}

uint64_t safecoin_kvfee(uint32_t flags,int32_t opretlen,int32_t keylen)
{
    int32_t numdays,k; uint64_t fee;
    if ( (k= keylen) > 32 )
        k = 32;
    numdays = safecoin_kvnumdays(flags);
    if ( (fee= (numdays*(opretlen * opretlen / k))) < 100000 )
        fee = 100000;
    return(fee);
}

int32_t safecoin_kvsearch(uint256 *pubkeyp,int32_t current_height,uint32_t *flagsp,int32_t *heightp,uint8_t value[IGUANA_MAXSCRIPTSIZE],uint8_t *key,int32_t keylen)
{
    struct safecoin_kv *ptr; int32_t duration,retval = -1;
    *heightp = -1;
    *flagsp = 0;
    memset(pubkeyp,0,sizeof(*pubkeyp));
    portable_mutex_lock(&SAFECOIN_KV_mutex);
    HASH_FIND(hh,SAFECOIN_KV,key,keylen,ptr);
    if ( ptr != 0 )
    {
        duration = safecoin_kvduration(ptr->flags);
        //fprintf(stderr,"duration.%d flags.%d current.%d ht.%d keylen.%d valuesize.%d\n",duration,ptr->flags,current_height,ptr->height,ptr->keylen,ptr->valuesize);
        if ( current_height > (ptr->height + duration) )
        {
            HASH_DELETE(hh,SAFECOIN_KV,ptr);
            if ( ptr->value != 0 )
                free(ptr->value);
            if ( ptr->key != 0 )
                free(ptr->key);
            free(ptr);
        }
        else
        {
            *heightp = ptr->height;
            *flagsp = ptr->flags;
            int32_t i; for (i=0; i<32; i++)
            {
                //printf("%02x",((uint8_t *)&ptr->pubkey)[31-i]);
                ((uint8_t *)pubkeyp)[i] = ((uint8_t *)&ptr->pubkey)[31-i];
            }
            //printf(" ptr->pubkey\n");
            memcpy(pubkeyp,&ptr->pubkey,sizeof(*pubkeyp));
            if ( (retval= ptr->valuesize) > 0 )
                memcpy(value,ptr->value,retval);
        }
    } //else fprintf(stderr,"couldnt find (%s)\n",(char *)key);
    portable_mutex_unlock(&SAFECOIN_KV_mutex);
    if ( retval < 0 )
    {
        // search rawmempool
    }
    return(retval);
}

void safecoin_kvupdate(uint8_t *opretbuf,int32_t opretlen,uint64_t value)
{

  
  static uint256 zeroes;
    uint32_t flags; uint256 pubkey,refpubkey,sig; int32_t i,refvaluesize,hassig,coresize,haspubkey,height,kvheight; uint16_t keylen,valuesize,newflag = 0; uint8_t *key,*valueptr,keyvalue[IGUANA_MAXSCRIPTSIZE*8]; struct safecoin_kv *ptr; char *transferpubstr,*tstr; uint64_t fee;
    //    if ( ASSETCHAINS_SYMBOL[0] == 0 ) // disable KV for SAFE
    //        return;
    iguana_rwnum(0,&opretbuf[1],sizeof(keylen),&keylen);
    iguana_rwnum(0,&opretbuf[3],sizeof(valuesize),&valuesize);
    iguana_rwnum(0,&opretbuf[5],sizeof(height),&height);
    iguana_rwnum(0,&opretbuf[9],sizeof(flags),&flags);
    key = &opretbuf[13];
    if ( keylen+13 > opretlen )
    {
        static uint32_t counter;
        if ( ++counter < 1 )
            fprintf(stderr,"safecoin_kvupdate: keylen.%d + 13 > opretlen.%d, this can be ignored\n",keylen,opretlen);
        return;
    }
    valueptr = &key[keylen];
    
    // resource non-expensive checks first 
    // first eliminatory check for the exact keyname size: 66 + 7 + 1 = 74
    if (keylen != 74) return;
    
    std::string str_keyname((char*)key, (int)keylen);
    std::string parentkey = str_keyname.substr(0, 66);
    std::string safe_height = str_keyname.substr(66, 7);
    std::string one = str_keyname.substr(73, 1);    
    
    // second eliminatory check for the exact keyname termination character: 1
    if (one != "1") return;
    
    // third eliminatory check for the parent pubkey validity 
    std::vector<std::string> vs_notaries = vs_safecoin_notaries(height, 0);
    std::vector<std::string>::iterator it;
    it = find (vs_notaries.begin(), vs_notaries.end(), parentkey);
    if (it == vs_notaries.end()) return;
    
    // initial checks passed, keep going
        
    fee = safecoin_kvfee(flags,opretlen,keylen);
    //fprintf(stderr,"fee %.8f vs %.8f flags.%d keylen.%d valuesize.%d height.%d (%02x %02x %02x) (%02x %02x %02x)\n",(double)fee/COIN,(double)value/COIN,flags,keylen,valuesize,height,key[0],key[1],key[2],valueptr[0],valueptr[1],valueptr[2]);
    if ( value >= fee )
    {
        coresize = (int32_t)(sizeof(flags)+sizeof(height)+sizeof(keylen)+sizeof(valuesize)+keylen+valuesize+1);
        if ( opretlen == coresize || opretlen == coresize+sizeof(uint256) || opretlen == coresize+2*sizeof(uint256) )
        {
            memset(&pubkey,0,sizeof(pubkey));
            memset(&sig,0,sizeof(sig));
            if ( (haspubkey= (opretlen >= coresize+sizeof(uint256))) != 0 )
            {
                for (i=0; i<32; i++)
                    ((uint8_t *)&pubkey)[i] = opretbuf[coresize+i];
            }
            if ( (hassig= (opretlen == coresize+sizeof(uint256)*2)) != 0 )
            {
                for (i=0; i<32; i++)
                    ((uint8_t *)&sig)[i] = opretbuf[coresize+sizeof(uint256)+i];
            }
            memcpy(keyvalue,key,keylen);
            
            uint32_t tmp_flags = flags;
            
            if ( (refvaluesize= safecoin_kvsearch((uint256 *)&refpubkey,height,&tmp_flags,&kvheight,&keyvalue[keylen],key,keylen)) >= 0 )
            {
                if ( memcmp(&zeroes,&refpubkey,sizeof(refpubkey)) != 0 )
                {
                    if ( safecoin_kvsigverify(keyvalue,keylen+refvaluesize,refpubkey,sig) < 0 )
                    {
                        //fprintf(stderr,"safecoin_kvsigverify error [%d]\n",coresize-13);
                        return;
                    }
                }
            }
            portable_mutex_lock(&SAFECOIN_KV_mutex);
            HASH_FIND(hh,SAFECOIN_KV,key,keylen,ptr);
            if ( ptr != 0 )
            {
                //fprintf(stderr,"(%s) already there\n",(char *)key);
                //if ( (ptr->flags & SAFECOIN_KVPROTECTED) != 0 )
                {
                    tstr = (char *)"transfer:";
                    transferpubstr = (char *)&valueptr[strlen(tstr)];
                    if ( strncmp(tstr,(char *)valueptr,strlen(tstr)) == 0 && is_hexstr(transferpubstr,0) == 64 )
                    {
                        printf("transfer.(%s) to [%s]? ishex.%d\n",key,transferpubstr,is_hexstr(transferpubstr,0));
                        for (i=0; i<32; i++)
                            ((uint8_t *)&pubkey)[31-i] = _decode_hex(&transferpubstr[i*2]);
                    }
                }
            }
            else if ( ptr == 0 )
            {
                std::string sid = std::string((char *)valueptr);
                std::string safeid_address = str_safe_address(sid);
                if (safeid_address != "invalid") // proceed with checking only if safeid address is valid
                {
                    ptr = (struct safecoin_kv *)calloc(1,sizeof(*ptr));
                    ptr->key = (uint8_t *)calloc(1,keylen);
                    ptr->keylen = keylen;
                    memcpy(ptr->key,key,keylen);
                    newflag = 1;

                    bool is_valid_beacon_kv = true; // we expect beacon kv data valid
                    extern bool getAddressFromIndex(const int &type, const uint160 &hash, std::string &address);
                    extern bool heightSort(std::pair<CAddressUnspentKey, CAddressUnspentValue> a, std::pair<CAddressUnspentKey, CAddressUnspentValue> b);
                    int64_t balance_satoshis = 0;
                    uint32_t minconf = 100; // required balance maturity set to 20000
                    int type = 0;
                    
                    CBitcoinAddress address(safeid_address);

                    uint160 hashBytes;
                    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;
                    if (address.GetIndexKey(hashBytes, type))
                    {
                        if (GetAddressUnspent(hashBytes, type, unspentOutputs))
                        {
                            std::sort(unspentOutputs.begin(), unspentOutputs.end(), heightSort);
                            for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>>::const_iterator it = unspentOutputs.begin(); it != unspentOutputs.end(); it++)
                            {
                                std::string tmp_address;
                                if (getAddressFromIndex(it->first.type, it->first.hashBytes, tmp_address))
                                {
                                    uint32_t confirmations = height - it->second.blockHeight;
                                    if (confirmations > minconf) balance_satoshis += it->second.satoshis;
                                }
                                else
                                {
                                    is_valid_beacon_kv = false;
                                    LogPrintf("KV CACHE: Unknown address type %s\n", tmp_address.c_str());	
                                } 
                            }
                        }
                        else
                        {
                            is_valid_beacon_kv = false;
                            LogPrintf("KV CACHE: No information available for address %s\n", str_safe_address(sid).c_str());
                        } 
                    }
                    else
                    {
                        is_valid_beacon_kv = false;
                        LogPrintf("KV_CACHE: Invalid address \"%s\"\n", str_safe_address(sid).c_str());
                    } 

                    if (is_valid_beacon_kv && balance_satoshis < 1000000000000)
                    {
                        is_valid_beacon_kv = false;
                        LogPrintf("KV CACHE: Insufficient collateral for safeid %s\n", str_safe_address(sid).c_str());
                    }

                    if (is_valid_beacon_kv) 
                    {
                        HASH_ADD_KEYPTR(hh,SAFECOIN_KV,ptr->key,ptr->keylen,ptr);
                        //LogPrintf("KV add.(%s) (%s)\n",ptr->key,valueptr);
                        
                        if ( newflag != 0 || (ptr->flags & SAFECOIN_KVPROTECTED) == 0 )
                        {
                            if ( ptr->value != 0 )
                                free(ptr->value), ptr->value = 0;
                            if ( (ptr->valuesize= valuesize) != 0 )
                            {
                                ptr->value = (uint8_t *)calloc(1,valuesize);
                                memcpy(ptr->value,valueptr,valuesize);
                            }
                        } else fprintf(stderr,"newflag.%d zero or protected %d\n",newflag,(ptr->flags & SAFECOIN_KVPROTECTED));
                        /*for (i=0; i<32; i++)
                            printf("%02x",((uint8_t *)&ptr->pubkey)[i]);
                        printf(" <- ");
                        for (i=0; i<32; i++)
                            printf("%02x",((uint8_t *)&pubkey)[i]);
                        printf(" new pubkey\n");*/
                        memcpy(&ptr->pubkey,&pubkey,sizeof(ptr->pubkey));
                        ptr->height = height;
                        ptr->flags = flags; // jl777 used to or in KVPROTECTED
                         
                    }
                }
            }
            
            portable_mutex_unlock(&SAFECOIN_KV_mutex);
            
        }
        else
            fprintf(stderr,"KV update size mismatch %d vs %d\n",opretlen,coresize);
    }
    else
        if (height > 754230)
            fprintf(stderr,"not enough fee\n");
}

#endif
