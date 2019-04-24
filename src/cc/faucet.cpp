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

#include "CCfaucet.h"
#include "../txmempool.h"

/*
 This file implements a simple CC faucet as an example of how to make a new CC contract. It wont have any fancy sybil protection but will serve the purpose of a fully automated faucet.

 In order to implement a faucet, we need to have it funded. Once it is funded, anybody should be able to get some reasonable small amount.

 This leads to needing to lock the funding in a CC protected output. And to put a spending limit. We can do a per transaction spending limit quite easily with vout constraints. However, that would allow anybody to issue thousands of transactions per block, so we also need to add a rate limiter.

 To implement this, we can simply make any faucet vout fund the faucet. Then we can limit the number of confirmed utxo by combining faucet outputs and then only using utxo which are confirmed. This combined with a vout size limit will drastically limit the funds that can be withdrawn from the faucet.
*/

// start of consensus code

int64_t IsFaucetvout(struct CCcontract_info *cp,const CTransaction& tx,int32_t v)
{
    char destaddr[64];
    if (tx.vout[v].scriptPubKey.IsPayToCryptoCondition() && Getscriptaddress(destaddr,tx.vout[v].scriptPubKey) && strcmp(destaddr,cp->unspendableCCaddr) == 0)
        return tx.vout[v].nValue;
    return 0;
}

bool FaucetExactAmounts(struct CCcontract_info *cp,Eval* eval,const CTransaction &tx,int32_t minage,uint64_t txfee)
{
    static uint256 zerohash;
    CTransaction vinTx; uint256 hashBlock,activehash; int32_t i,numvouts; int64_t inputs=0,outputs=0;
    numvouts = tx.vout.size();
    for (auto txvin : tx.vin)
    {
        //fprintf(stderr,"vini.%d\n",i);
        if ((*cp->ismyvin)(txvin.scriptSig))
        {
            //fprintf(stderr,"vini.%d check mempool\n",i);
            if (!eval->GetTxUnconfirmed(txvin.prevout.hash,vinTx,hashBlock))
                return eval->Invalid("cant find vinTx");
            //fprintf(stderr,"vini.%d check hash and vout\n",i);
            if ( hashBlock == zerohash )
                return eval->Invalid("cant faucet from mempool");
            inputs += IsFaucetvout(cp,vinTx,txvin.prevout.n);
        }
    }
    for (i=0; i<numvouts; i++)
    {
        //fprintf(stderr,"i.%d of numvouts.%d\n",i,numvouts);
        outputs += IsFaucetvout(cp,tx,i);
    }
    if ( inputs != outputs+FAUCETSIZE+txfee )
    {
        fprintf(stderr,"inputs %llu vs outputs %llu\n",(long long)inputs,(long long)outputs);
        return eval->Invalid("mismatched inputs != outputs + FAUCETSIZE + txfee");
    }
    return true;
}

bool FaucetValidate(struct CCcontract_info *cp,Eval* eval,const CTransaction &tx, uint32_t nIn)
{
    int32_t numvins,numvouts,preventCCvins,preventCCvouts,i,numblocks; bool retval; uint256 txid; uint8_t hash[32]; char str[65],destaddr[64];
    std::vector<std::pair<CAddressIndexKey, CAmount> > txids;
    numvins = tx.vin.size();
    numvouts = tx.vout.size();
    preventCCvins = preventCCvouts = -1;
    if ( numvouts < 1 )
        return eval->Invalid("no vouts");
    else
    {
        //TODO: Useless loop
        for (i=0; i<numvins; i++)
        {
            if (!IsCCInput(tx.vin[0].scriptSig))
            {
                fprintf(stderr,"faucetget invalid vini\n");
                return eval->Invalid("illegal normal vini");
            }
        }
        //fprintf(stderr,"check amounts\n");
        if (!FaucetExactAmounts(cp, eval, tx, 1, 10000))
        {
            fprintf(stderr,"faucetget invalid amount\n");
            return false;
        }
        i = IsFaucetvout(cp,tx,0) != 0 ? 1 : 0;
        preventCCvouts = 1 + i;
        txid = tx.GetHash();
        memcpy(hash,&txid,sizeof(hash));
        fprintf(stderr,"check faucetget txid %s %02x/%02x\n",uint256_str(str,txid),hash[0],hash[31]);
        if ( tx.vout[i].nValue != FAUCETSIZE )
            return eval->Invalid("invalid faucet output");
        if ( hash[0] & 0xff != 0 || hash[31] & 0xff != 0 )
            return eval->Invalid("invalid faucetget txid");
        Getscriptaddress(destaddr,tx.vout[i].scriptPubKey);
        SetCCtxids(txids,destaddr);
        for (auto txid : txids)
        {
            //int height = txid.first.blockHeight;
            if ( CCduration(numblocks,txid.first.txhash) > 0 && numblocks > 3 )
            {
                //fprintf(stderr,"would return error %s numblocks.%d ago\n",uint256_str(str,it->first.txhash),numblocks);
                return eval->Invalid("faucet is only for brand new addresses");
            }
        }
        retval = PreventCC(eval,tx,preventCCvins,numvins,preventCCvouts,numvouts);
        if (retval)
            fprintf(stderr,"faucetget validated\n");
        else
            fprintf(stderr,"faucetget invalid\n");
        return retval;
    }
}
// end of consensus code

// helper functions for rpc calls in rpcwallet.cpp

int64_t AddFaucetInputs(struct CCcontract_info *cp,CMutableTransaction &mtx,CPubKey pk,int64_t total,int32_t maxinputs)
{
    char coinaddr[64]; int64_t threshold,nValue,price,totalinputs = 0; uint256 txid,hashBlock; std::vector<uint8_t> origpubkey; CTransaction vintx; int32_t vout,n = 0;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;
    GetCCaddress(cp,coinaddr,pk);
    SetCCunspents(unspentOutputs,coinaddr);
    threshold = total/(maxinputs+1);
    for (auto unspentOutput : unspentOutputs)
    {
        txid = unspentOutput.first.txhash;
        vout = (int32_t)unspentOutput.first.index;
        if ( unspentOutput.second.satoshis < threshold )
            continue;
        //char str[65]; fprintf(stderr,"check %s/v%d %.8f`\n",uint256_str(str,txid),vout,(double)it->second.satoshis/COIN);
        // no need to prevent dup
        if (GetTransaction(txid,vintx,hashBlock,false))
        {
            if ( (nValue= IsFaucetvout(cp,vintx,vout)) > 1000000 && myIsutxo_spentinmempool(txid,vout) == 0 )
            {
                if ( total != 0 && maxinputs != 0 )
                    mtx.vin.push_back(CTxIn(txid,vout,CScript()));
                nValue = unspentOutput.second.satoshis;
                totalinputs += nValue;
                n++;
                if ( (total > 0 && totalinputs >= total) || (maxinputs > 0 && n >= maxinputs) )
                    break;
            } else fprintf(stderr,"nValue too small or already spent in mempool\n");
        } else fprintf(stderr,"couldnt get tx\n");
    }
    return totalinputs;
}

std::string FaucetGet(uint64_t txfee)
{
    CMutableTransaction tmpmtx,mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), safecoin_nextheight());
    CPubKey mypk,faucetpk; int64_t inputs,CCchange=0,nValue=FAUCETSIZE; struct CCcontract_info *cp,C; std::string rawhex; uint32_t j; int32_t i,len; uint8_t buf[32768]; bits256 hash;
    cp = CCinit(&C,EVAL_FAUCET);
    if ( txfee == 0 )
        txfee = 10000;
    faucetpk = GetUnspendable(cp, nullptr);
    mypk = pubkey2pk(Mypubkey());
    if ( (inputs= AddFaucetInputs(cp,mtx,faucetpk,nValue+txfee,60)) > 0 )
    {
        if ( inputs > nValue )
            CCchange = inputs - nValue - txfee;
        if ( CCchange != 0 )
            mtx.vout.push_back(MakeCC1vout(EVAL_FAUCET,CCchange,faucetpk));
        mtx.vout.push_back(CTxOut(nValue,CScript() << ParseHex(HexStr(mypk)) << OP_CHECKSIG));
        fprintf(stderr,"start at %u\n",(uint32_t)time(NULL));
        j = rand() & 0xfffffff;
        for (i=0; i<1000000; i++,j++)
        {
            tmpmtx = mtx;
            rawhex = FinalizeCCTx(-1LL,cp,tmpmtx,mypk,txfee,CScript() << OP_RETURN << E_MARSHAL(ss << (uint8_t)EVAL_FAUCET << (uint8_t)'G' << j));
            if ( (len= (int32_t)rawhex.size()) > 0 && len < 65536 )
            {
                len >>= 1;
                decode_hex(buf,len,(char *)rawhex.c_str());
                hash = bits256_doublesha256(nullptr,buf,len);
                if ( (hash.bytes[0] & 0xff) == 0 && (hash.bytes[31] & 0xff) == 0 )
                {
                    fprintf(stderr,"found valid txid after %d iterations %u\n",i,(uint32_t)time(NULL));
                    return rawhex;
                }
                //fprintf(stderr,"%02x%02x ",hash.bytes[0],hash.bytes[31]);
            }
        }
        fprintf(stderr,"couldnt generate valid txid %u\n",(uint32_t)time(NULL));
        return "";
    }
    fprintf(stderr,"cant find faucet inputs\n");
    return "";
}

std::string FaucetFund(uint64_t txfee,int64_t funds)
{
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), safecoin_nextheight());
    CPubKey mypk,faucetpk; CScript opret; struct CCcontract_info *cp,C;
    cp = CCinit(&C,EVAL_FAUCET);
    if ( txfee == 0 )
        txfee = 10000;
    mypk = pubkey2pk(Mypubkey());
    faucetpk = GetUnspendable(cp, nullptr);
    if ( AddNormalinputs(mtx,mypk,funds+txfee,64) > 0 )
    {
        mtx.vout.push_back(MakeCC1vout(EVAL_FAUCET,funds,faucetpk));
        return FinalizeCCTx(0,cp,mtx,mypk,txfee,opret);
    }
    return "";
}

UniValue FaucetInfo()
{
    UniValue result(UniValue::VOBJ); char numstr[64];
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(Params().GetConsensus(), safecoin_nextheight());
    CPubKey faucetpk; struct CCcontract_info *cp,C; int64_t funding;
    result.push_back(Pair("result","success"));
    result.push_back(Pair("name","Faucet"));
    cp = CCinit(&C,EVAL_FAUCET);
    faucetpk = GetUnspendable(cp, nullptr);
    funding = AddFaucetInputs(cp,mtx,faucetpk,0,0);
    sprintf(numstr,"%.8f",(double)funding/COIN);
    result.push_back(Pair("funding",numstr));
    return result;
}

