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

#include "CCinclude.h"
#include "key_io.h"

/*
 FinalizeCCTx is a very useful function that will properly sign both CC and normal inputs, adds normal change and the opreturn.

 This allows the contract transaction functions to create the appropriate vins and vouts and have FinalizeCCTx create a properly signed transaction.

 By using -addressindex=1, it allows tracking of all the CC addresses
 */

bool SignTx(CMutableTransaction &mtx,int32_t vini,int64_t utxovalue,const CScript scriptPubKey)
{
#ifdef ENABLE_WALLET
    CTransaction txNewConst(mtx); SignatureData sigdata; const CKeyStore& keystore = *pwalletMain;
    auto consensusBranchId = CurrentEpochBranchId(chainActive.Height() + 1, Params().GetConsensus());
    if ( ProduceSignature(TransactionSignatureCreator(&keystore,&txNewConst,vini,utxovalue,SIGHASH_ALL),scriptPubKey,sigdata,consensusBranchId) != 0 )
    {
        UpdateTransaction(mtx,vini,sigdata);
        return true;
    }
    fprintf(stderr,"signing error for SignTx vini.%d %.8f\n",vini,(double)utxovalue/COIN);
#endif
    return false;
}

std::string FinalizeCCTx(uint64_t CCmask,struct CCcontract_info *cp,CMutableTransaction &mtx,CPubKey mypk,uint64_t txfee,CScript opret)
{
    auto consensusBranchId = CurrentEpochBranchId(chainActive.Height() + 1, Params().GetConsensus());
    CTransaction vintx; std::string hex; uint256 hashBlock; uint64_t mask=0,nmask=0,vinimask=0;
    int64_t utxovalues[64],change,normalinputs=0,totaloutputs=0,normaloutputs=0,totalinputs=0,normalvins=0,ccvins=0;
    int32_t i,utxovout,n,err = 0; char myaddr[64],destaddr[64],unspendable[64];
    uint8_t *privkey,myprivkey[32],unspendablepriv[32],*msg32 = 0; CC *mycond=0,*othercond=0,*othercond2=0,*othercond3=0,*cond; CPubKey unspendablepk;
    for (auto mtxvout : mtx.vout)
    {
        if ( !mtxvout.scriptPubKey.IsPayToCryptoCondition() )
            normaloutputs += mtxvout.nValue;
        totaloutputs += mtxvout.nValue;
    }
    if ( (n= mtx.vin.size()) > 64 )
    {
        fprintf(stderr,"FinalizeCCTx: %d is too many vins\n",n);
        return "0";
    }
    Myprivkey(myprivkey);
    unspendablepk = GetUnspendable(cp,unspendablepriv);
    GetCCaddress(cp,myaddr,mypk);
    mycond = MakeCCcond1(cp->evalcode,mypk);
    GetCCaddress(cp,unspendable,unspendablepk);
    othercond = MakeCCcond1(cp->evalcode,unspendablepk);
    //Reorder vins so that for multiple normal vins all other except vin0 goes to the end
    //This is a must to avoid hardfork change of validation in every CC, because there could be maximum one normal vin at the begining with current validation.
    for (auto mtxvin : mtx.vin)
    {
        if ( GetTransaction(mtxvin.prevout.hash,vintx,hashBlock,false) )
        {
            if ( !vintx.vout[mtxvin.prevout.n].scriptPubKey.IsPayToCryptoCondition() && ccvins==0)
                ++normalvins;
            else
                ++ccvins;
        }
    }
    if (normalvins > 1 && ccvins != 0)
    {
        for(i=1;i<normalvins;i++)
        {
            mtx.vin.push_back(mtx.vin[1]);
            mtx.vin.erase(mtx.vin.begin() + 1);
        }
    }
    memset(utxovalues,0,sizeof(utxovalues));
    for (auto mtxvin : mtx.vin)
    {
        if ( GetTransaction(mtxvin.prevout.hash,vintx,hashBlock,false) )
        {
            utxovout = mtx.vin[i].prevout.n;
            utxovalues[i] = vintx.vout[utxovout].nValue;
            totalinputs += utxovalues[i];
            if ( !vintx.vout[utxovout].scriptPubKey.IsPayToCryptoCondition() )
            {
                //fprintf(stderr,"vin.%d is normal %.8f\n",i,(double)utxovalues[i]/COIN);
                normalinputs += utxovalues[i];
                vinimask |= 1LL << i;
            }
            else
            {
                mask |= 1LL << i;
            }
        } else fprintf(stderr,"FinalizeCCTx couldnt find %s\n",mtx.vin[i].prevout.hash.ToString().c_str());
    }
    nmask = (1LL << n) - 1;
    if ( 0 && (mask & nmask) != (CCmask & nmask) )
        fprintf(stderr,"mask.%llx vs CCmask.%llx %llx %llx %llx\n",(long long)(mask & nmask),(long long)(CCmask & nmask),(long long)mask,(long long)CCmask,(long long)nmask);
    if ( totalinputs >= totaloutputs+2*txfee )
    {
        change = totalinputs - totaloutputs - txfee;
        mtx.vout.push_back(CTxOut(change,CScript() << ParseHex(HexStr(mypk)) << OP_CHECKSIG));
    }
    if ( !opret.empty() )
        mtx.vout.push_back(CTxOut(0,opret));
    PrecomputedTransactionData txdata(mtx);
    n = mtx.vin.size();
    for (i = 0; i < n; i++)
    {
        if ( GetTransaction(mtx.vin[i].prevout.hash,vintx,hashBlock,false) )
        {
            utxovout = mtx.vin[i].prevout.n;
            if ( !vintx.vout[utxovout].scriptPubKey.IsPayToCryptoCondition() )
            {
                if ( !SignTx(mtx,i,vintx.vout[utxovout].nValue,vintx.vout[utxovout].scriptPubKey) )
                    fprintf(stderr,"signing error for vini.%d of %llx\n",i,(long long)vinimask);
            }
            else
            {
                Getscriptaddress(destaddr,vintx.vout[utxovout].scriptPubKey);
                //fprintf(stderr,"vin.%d is CC %.8f -> (%s)\n",i,(double)utxovalues[i]/COIN,destaddr);
                if ( strcmp(destaddr,myaddr) == 0 )
                {
                    privkey = myprivkey;
                    cond = mycond;

                }
                else if ( strcmp(destaddr,unspendable) == 0 )
                {
                    privkey = unspendablepriv;
                    cond = othercond;
                    //fprintf(stderr,"unspendable CC addr.(%s)\n",unspendable);
                }
                else if ( strcmp(destaddr,cp->unspendableaddr2) == 0)
                {
                    //fprintf(stderr,"matched %s unspendable2!\n",cp->unspendableaddr2);
                    privkey = cp->unspendablepriv2;
                    if ( othercond2 == nullptr && cp->evalcode != EVAL_CHANNELS && cp->evalcode != EVAL_HEIR )
                        othercond2 = MakeCCcond1(cp->evalcode2,cp->unspendablepk2);
                    else if ( othercond2 == nullptr && (cp->evalcode == EVAL_CHANNELS || cp->evalcode == EVAL_HEIR) )
                        othercond2 = MakeCCcond1of2(cp->evalcode2,cp->unspendablepk2,cp->unspendablepk3);
                    cond = othercond2;
                }
                else if ( strcmp(destaddr,cp->unspendableaddr3) == 0 )
                {
                    //fprintf(stderr,"matched %s unspendable3!\n",cp->unspendableaddr3);
                    privkey = cp->unspendablepriv3;
                    if ( othercond3 == nullptr )
                        othercond3 = MakeCCcond1(cp->evalcode3,cp->unspendablepk3);
                    cond = othercond3;
                }
                else
                {
                    fprintf(stderr,"CC signing error: vini.%d has unknown CC address.(%s)\n",i,destaddr);
                    continue;
                }
                uint256 sighash = SignatureHash(CCPubKey(cond), mtx, i, SIGHASH_ALL, utxovalues[i],consensusBranchId, &txdata);
                if ( cc_signTreeSecp256k1Msg32(cond,privkey,sighash.begin()) != 0 )
                {
                    //int32_t z;
                    //for (z=0; z<32; z++)
                    //    fprintf(stderr,"%02x",((uint8_t *)sighash.begin())[z]);
                    //fprintf(stderr," sighash, ");
                    //for (z=0; z<32; z++)
                    //   fprintf(stderr,"%02x",privkey[z]);
                    //fprintf(stderr," signed with privkey\n");
                    mtx.vin[i].scriptSig = CCSig(cond);
                }
                else
                {
                    fprintf(stderr,"vini.%d has CC signing error address.(%s)\n",i,destaddr);
                }
            }
        } else fprintf(stderr,"FinalizeCCTx couldnt find %s\n",mtx.vin[i].prevout.hash.ToString().c_str());
    }
    if ( mycond != nullptr )
        cc_free(mycond);
    if ( othercond != nullptr )
        cc_free(othercond);
    if ( othercond2 != nullptr )
        cc_free(othercond2);
    if ( othercond3 != nullptr )
        cc_free(othercond3);
    std::string strHex = EncodeHexTx(mtx);
    if ( !strHex.empty() )
        return strHex;
    return "0";
}

void SetCCunspents(std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs,char *coinaddr)
{
    int32_t type=0,i,n; char *ptr; std::string addrstr; uint160 hashBytes; std::vector<std::pair<uint160, int> > addresses;
    n = (int32_t)strlen(coinaddr);
    addrstr.resize(n+1);
    ptr = (char *)addrstr.data();
    for (i=0; i<=n; i++)
        ptr[i] = coinaddr[i];
    CBitcoinAddress address(addrstr);
    if (!address.GetIndexKey(hashBytes, type))
        return;
    addresses.push_back(std::make_pair(hashBytes,type));
    for (auto address : addresses)
        if (!GetAddressUnspent(address.first, address.second, unspentOutputs))
            return;
}

void SetCCtxids(std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,char *coinaddr)
{
    int32_t type=0,i,n; char *ptr; std::string addrstr; uint160 hashBytes; std::vector<std::pair<uint160, int> > addresses;
    n = (int32_t)strlen(coinaddr);
    addrstr.resize(n+1);
    ptr = (char *)addrstr.data();
    for (i=0; i<=n; i++)
        ptr[i] = coinaddr[i];
    CBitcoinAddress address(addrstr);
    if (!address.GetIndexKey(hashBytes, type))
        return;
    addresses.push_back(std::make_pair(hashBytes,type));
    for (auto address : addresses)
        if ( !GetAddressIndex(address.first, address.second, addressIndex) )
            return;
}

int64_t CCutxovalue(char *coinaddr,uint256 utxotxid,int32_t utxovout)
{
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;
    SetCCunspents(unspentOutputs,coinaddr);
    for (auto unspentOutput : unspentOutputs)
        if (utxotxid == unspentOutput.first.txhash && utxovout == unspentOutput.first.index)
            return unspentOutput.second.satoshis;
    return 0;
}

int64_t CCaddress_balance(char *coinaddr)
{
    int64_t sum = 0; std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;
    SetCCunspents(unspentOutputs,coinaddr);
    for (auto unspentOutput : unspentOutputs)
        sum += unspentOutput.second.satoshis;
    return sum;
}

int64_t CCfullsupply(uint256 tokenid)
{
    uint256 hashBlock; CTransaction tx; std::vector<uint8_t> origpubkey; std::string name,description;
    if ( GetTransaction(tokenid,tx,hashBlock,false) && !tx.vout.empty() )
        if ( DecodeAssetCreateOpRet(tx.vout.back().scriptPubKey,origpubkey,name,description) )
            return tx.vout[0].nValue;
    return 0;
}

int64_t CCtoken_balance(char *coinaddr,uint256 tokenid)
{
    int64_t price,sum = 0; CTransaction tx; uint256 assetid,assetid2,txid,hashBlock; std::vector<uint8_t> origpubkey;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;
    SetCCunspents(unspentOutputs,coinaddr);
    for (auto unspentOutput : unspentOutputs)
    {
        txid = unspentOutput.first.txhash;
        if ( GetTransaction(txid,tx,hashBlock,false) && !tx.vout.empty() )
        {
            char str[65];
            fprintf(stderr,"check %s %.8f\n",uint256_str(str,txid),(double)unspentOutput.second.satoshis/COIN);
            if ( DecodeAssetOpRet(tx.vout.back().scriptPubKey,assetid,assetid2,price,origpubkey) != 0 && assetid == tokenid )
                sum += unspentOutput.second.satoshis;
        }
    }
    return sum;
}

int32_t CC_vinselect(int32_t *aboveip,int64_t *abovep,int32_t *belowip,int64_t *belowp,struct CC_utxo utxos[],int32_t numunspents,int64_t value)
{
    int32_t i,abovei,belowi; int64_t above,below,gap,atx_value;
    abovei = belowi = -1;
    for (above=below=i=0; i<numunspents; i++)
    {
        // Filter to randomly pick utxo to avoid conflicts, and having multiple CC choose the same ones.
        //if ( numunspents > 200 ) {
        //    if ( (rand() % 100) < 90 )
        //        continue;
        //}
        if ( (atx_value= utxos[i].nValue) <= 0 )
            continue;
        if ( atx_value == value )
        {
            *aboveip = *belowip = i;
            *abovep = *belowp = 0;
            return i;
        }
        else if ( atx_value > value )
        {
            gap = atx_value - value;
            if ( above == 0 || gap < above )
            {
                above = gap;
                abovei = i;
            }
        }
        else
        {
            gap = value - atx_value;
            if ( below == 0 || gap < below )
            {
                below = gap;
                belowi = i;
            }
        }
        //printf("value %.8f gap %.8f abovei.%d %.8f belowi.%d %.8f\n",dstr(value),dstr(gap),abovei,dstr(above),belowi,dstr(below));
    }
    *aboveip = abovei;
    *abovep = above;
    *belowip = belowi;
    *belowp = below;
    //printf("above.%d below.%d\n",abovei,belowi);
    if ( abovei >= 0 )
    {
        if (belowi >= 0 && above >= (below >> 1) )
            return belowi;
        return abovei;
    }
    return belowi;
}

int64_t AddNormalinputs(CMutableTransaction &mtx,CPubKey mypk,int64_t total,int32_t maxinputs)
{
    int32_t abovei,belowi,ind,vout,i,n = 0,maxutxos=64; int64_t sum,threshold,above,below; int64_t remains,nValue,totalinputs = 0; uint256 txid,hashBlock; std::vector<COutput> vecOutputs; CTransaction tx; struct CC_utxo *utxos,*up;
#ifdef ENABLE_WALLET
    const CKeyStore& keystore = *pwalletMain;
    assert(pwalletMain != nullptr);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    pwalletMain->AvailableCoins(vecOutputs, false, nullptr, true);
    utxos = (struct CC_utxo *)calloc(maxutxos,sizeof(*utxos));
    threshold = total/(maxinputs+1);
    if ( maxinputs > maxutxos )
        maxutxos = maxinputs;
    sum = 0;
    for (const COutput& out : vecOutputs) {
        if ( out.fSpendable && out.tx->vout[out.i].nValue >= threshold )
        {
            txid = out.tx->GetHash();
            vout = out.i;
            if ( myGetTransaction(txid,tx,hashBlock) && !tx.vout.empty() && vout < tx.vout.size() && !tx.vout[vout].scriptPubKey.IsPayToCryptoCondition() )
            {
                //fprintf(stderr,"check %.8f to vins array.%d of %d %s/v%d\n",(double)out.tx->vout[out.i].nValue/COIN,n,maxutxos,txid.GetHex().c_str(),(int32_t)vout);
                if ( !mtx.vin.empty() )
                {
                    for (i=0; i<mtx.vin.size(); i++)
                        if ( txid == mtx.vin[i].prevout.hash && vout == mtx.vin[i].prevout.n )
                            break;
                    if ( i != mtx.vin.size() )
                        continue;
                }
                if ( n > 0 )
                {
                    for (i=0; i<n; i++)
                        if ( txid == utxos[i].txid && vout == utxos[i].vout )
                            break;
                    if ( i != n )
                        continue;
                }
                if ( !myIsutxo_spentinmempool(txid,vout) )
                {
                    up = &utxos[n++];
                    up->txid = txid;
                    up->nValue = out.tx->vout[out.i].nValue;
                    up->vout = vout;
                    sum += up->nValue;
                    //fprintf(stderr,"add %.8f to vins array.%d of %d\n",(double)up->nValue/COIN,n,maxutxos);
                    if ( n >= maxutxos || sum >= total )
                        break;
                }
            }
        }
    }
    remains = total;
    for (i=0; i<maxinputs && n>0; i++)
    {
        below = above = 0;
        abovei = belowi = -1;
        if ( CC_vinselect(&abovei,&above,&belowi,&below,utxos,n,remains) < 0 )
        {
            printf("error finding unspent i.%d of %d, %.8f vs %.8f\n",i,n,(double)remains/COIN,(double)total/COIN);
            free(utxos);
            return 0;
        }
        ind = belowi < 0 || abovei >= 0 ? abovei : belowi;
        if ( ind < 0 )
        {
            printf("error finding unspent i.%d of %d, %.8f vs %.8f, abovei.%d belowi.%d ind.%d\n",i,n,(double)remains/COIN,(double)total/COIN,abovei,belowi,ind);
            free(utxos);
            return 0;
        }
        up = &utxos[ind];
        mtx.vin.push_back(CTxIn(up->txid,up->vout,CScript()));
        totalinputs += up->nValue;
        remains -= up->nValue;
        utxos[ind] = utxos[--n];
        memset(&utxos[n],0,sizeof(utxos[n]));
        //fprintf(stderr,"totalinputs %.8f vs total %.8f i.%d vs max.%d\n",(double)totalinputs/COIN,(double)total/COIN,i,maxinputs);
        if ( totalinputs >= total || i+1 >= maxinputs )
            break;
    }
    free(utxos);
    if ( totalinputs >= total )
        return totalinputs;
#endif
    return 0;
}


int64_t AddNormalinputs2(CMutableTransaction &mtx,int64_t total,int32_t maxinputs)
{
    int32_t abovei,belowi,ind,vout,i,n = 0,maxutxos=64; int64_t sum,threshold,above,below; int64_t remains,nValue,totalinputs = 0; char coinaddr[64]; uint256 txid,hashBlock; CTransaction tx; struct CC_utxo *utxos,*up;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;
    utxos = (struct CC_utxo *)calloc(maxutxos,sizeof(*utxos));
    threshold = total/(maxinputs+1);
    if ( maxinputs > maxutxos )
        maxutxos = maxinputs;
    sum = 0;
    Getscriptaddress(coinaddr,CScript() << Mypubkey() << OP_CHECKSIG);
    SetCCunspents(unspentOutputs,coinaddr);
    for (auto unspentOutput : unspentOutputs)
    {
        txid = unspentOutput.first.txhash;
        vout = (int32_t)unspentOutput.first.index;
        if ( unspentOutput.second.satoshis < threshold )
            continue;
        if ( myGetTransaction(txid,tx,hashBlock) && !tx.vout.empty() && vout < tx.vout.size() && !tx.vout[vout].scriptPubKey.IsPayToCryptoCondition() )
        {
            //fprintf(stderr,"check %.8f to vins array.%d of %d %s/v%d\n",(double)out.tx->vout[out.i].nValue/COIN,n,maxutxos,txid.GetHex().c_str(),(int32_t)vout);
            if ( !mtx.vin.empty() )
            {
                for (i=0; i<mtx.vin.size(); i++)
                    if ( txid == mtx.vin[i].prevout.hash && vout == mtx.vin[i].prevout.n )
                        break;
                if ( i != mtx.vin.size() )
                    continue;
            }
            if ( n > 0 )
            {
                for (i=0; i<n; i++)
                    if ( txid == utxos[i].txid && vout == utxos[i].vout )
                        break;
                if ( i != n )
                    continue;
            }
            if ( !myIsutxo_spentinmempool(txid,vout) )
            {
                up = &utxos[n++];
                up->txid = txid;
                up->nValue = unspentOutput.second.satoshis;
                up->vout = vout;
                sum += up->nValue;
                //fprintf(stderr,"add %.8f to vins array.%d of %d\n",(double)up->nValue/COIN,n,maxutxos);
                if ( n >= maxutxos || sum >= total )
                    break;
            }
        }
    }
    remains = total;
    for (i=0; i<maxinputs && n>0; i++)
    {
        below = above = 0;
        abovei = belowi = -1;
        if ( CC_vinselect(&abovei,&above,&belowi,&below,utxos,n,remains) < 0 )
        {
            printf("error finding unspent i.%d of %d, %.8f vs %.8f\n",i,n,(double)remains/COIN,(double)total/COIN);
            free(utxos);
            return 0;
        }
        ind = belowi < 0 || abovei >= 0 ? abovei : belowi;
        if ( ind < 0 )
        {
            printf("error finding unspent i.%d of %d, %.8f vs %.8f, abovei.%d belowi.%d ind.%d\n",i,n,(double)remains/COIN,(double)total/COIN,abovei,belowi,ind);
            free(utxos);
            return 0;
        }
        up = &utxos[ind];
        mtx.vin.push_back(CTxIn(up->txid,up->vout,CScript()));
        totalinputs += up->nValue;
        remains -= up->nValue;
        utxos[ind] = utxos[--n];
        memset(&utxos[n],0,sizeof(utxos[n]));
        //fprintf(stderr,"totalinputs %.8f vs total %.8f i.%d vs max.%d\n",(double)totalinputs/COIN,(double)total/COIN,i,maxinputs);
        if ( totalinputs >= total || i+1 >= maxinputs )
            break;
    }
    free(utxos);
    if ( totalinputs >= total )
    {
        //fprintf(stderr,"return totalinputs %.8f\n",(double)totalinputs/COIN);
        return(totalinputs);
    }
    return 0;
}
