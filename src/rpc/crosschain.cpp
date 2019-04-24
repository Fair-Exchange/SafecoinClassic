#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "crosschain.h"
#include "notarisationdb.h"
#include "importcoin.h"
#include "base58.h"
#include "consensus/validation.h"
#include "cc/eval.h"
#include "cc/utils.h"
#include "main.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "sync.h"
#include "util.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"

#include <stdint.h>
#include <univalue.h>
#include <regex>


using namespace std;

int32_t safecoin_MoM(int32_t *notarized_htp,uint256 *MoMp,uint256 *safetxidp,int32_t nHeight,uint256 *MoMoMp,int32_t *MoMoMoffsetp,int32_t *MoMoMdepthp,int32_t *safestartip,int32_t *safeendip);
int8_t safecoin_MoMoMdata(char *hexstr,int32_t hexsize,struct safecoin_ccdataMoMoM *mdata,char *symbol,int32_t safeheight,int32_t notarized_height);
struct safecoin_ccdata_entry *safecoin_allMoMs(int32_t *nump,uint256 *MoMoMp,int32_t safestarti,int32_t safeendi);
uint256 safecoin_calcMoM(int32_t height,int32_t MoMdepth);


UniValue assetchainproof(const UniValue& params, bool fHelp)
{
    uint256 hash;

    // parse params and get notarisation data for tx
    if ( fHelp || params.size() != 1)
        throw runtime_error("assetchainproof needs a txid");

    hash = uint256S(params[0].get_str());

    auto proof = GetAssetchainProof(hash);
    auto proofData = E_MARSHAL(ss << proof);
    return HexStr(proofData);
}


UniValue crosschainproof(const UniValue& params, bool fHelp)
{
    UniValue ret(UniValue::VOBJ);
    //fprintf(stderr,"crosschainproof needs to be implemented\n");
    return ret;
}


UniValue height_MoM(const UniValue& params, bool fHelp)
{
    int32_t height,depth,notarized_height,MoMoMdepth,MoMoMoffset,safestarti,safeendi; uint256 MoM,MoMoM,safetxid; uint32_t timestamp = 0; UniValue ret(UniValue::VOBJ); UniValue a(UniValue::VARR);
    if ( fHelp || params.size() != 1 )
        throw runtime_error("height_MoM height\n");
    LOCK(cs_main);
    height = atoi(params[0].get_str().c_str());
    if ( height <= 0 )
    {
        if ( chainActive.Tip() == 0 )
        {
            ret.push_back(Pair("error",(char *)"no active chain yet"));
            return ret;
        }
        height = chainActive.Tip()->GetHeight();
    }
    //fprintf(stderr,"height_MoM height.%d\n",height);
    depth = safecoin_MoM(&notarized_height,&MoM,&safetxid,height,&MoMoM,&MoMoMoffset,&MoMoMdepth,&safestarti,&safeendi);
    ret.push_back(Pair("coin",(char *)(ASSETCHAINS_SYMBOL[0] == '\0' ? "SAFE" : ASSETCHAINS_SYMBOL)));
    ret.push_back(Pair("height",height));
    ret.push_back(Pair("timestamp",(uint64_t)timestamp));
    if ( depth > 0 )
    {
        ret.push_back(Pair("depth",depth));
        ret.push_back(Pair("notarized_height",notarized_height));
        ret.push_back(Pair("MoM",MoM.GetHex()));
        ret.push_back(Pair("safetxid",safetxid.GetHex()));
        if ( ASSETCHAINS_SYMBOL[0] != '\0' )
        {
            ret.push_back(Pair("MoMoM",MoMoM.GetHex()));
            ret.push_back(Pair("MoMoMoffset",MoMoMoffset));
            ret.push_back(Pair("MoMoMdepth",MoMoMdepth));
            ret.push_back(Pair("safestarti",safestarti));
            ret.push_back(Pair("safeendi",safeendi));
        }
    } else ret.push_back(Pair("error",(char *)"no MoM for height"));

    return ret;
}

UniValue MoMoMdata(const UniValue& params, bool fHelp)
{
    if ( fHelp || params.size() != 3 )
        throw runtime_error("MoMoMdata symbol safeheight ccid\n");
    UniValue ret(UniValue::VOBJ);
    char* symbol = (char *)params[0].get_str().c_str();
    int safeheight = atoi(params[1].get_str().c_str());
    uint32_t ccid = atoi(params[2].get_str().c_str());
    ret.push_back(Pair("coin",symbol));
    ret.push_back(Pair("safeheight",safeheight));
    ret.push_back(Pair("ccid", (int) ccid));

    uint256 destNotarisationTxid;
    std::vector<uint256> moms;
    uint256 MoMoM = CalculateProofRoot(symbol, ccid, safeheight, moms, destNotarisationTxid);

    UniValue valMoms(UniValue::VARR);
    for (auto mom : moms) valMoms.push_back(mom.GetHex());
    ret.push_back(Pair("MoMs", valMoms));
    ret.push_back(Pair("notarization_hash", destNotarisationTxid.GetHex()));
    ret.push_back(Pair("MoMoM", MoMoM.GetHex()));
    auto vmomomdata = E_MARSHAL(ss << MoMoM; ss << ((uint32_t)0));
    ret.push_back(Pair("data", HexStr(vmomomdata)));
    return ret;
}


UniValue calc_MoM(const UniValue& params, bool fHelp)
{
    int32_t height,MoMdepth; uint256 MoM; UniValue ret(UniValue::VOBJ); UniValue a(UniValue::VARR);
    if ( fHelp || params.size() != 2 )
        throw runtime_error("calc_MoM height MoMdepth\n");
    LOCK(cs_main);
    height = atoi(params[0].get_str().c_str());
    MoMdepth = atoi(params[1].get_str().c_str());
    if ( height <= 0 || MoMdepth <= 0 || MoMdepth >= height )
        throw runtime_error("calc_MoM illegal height or MoMdepth\n");
    //fprintf(stderr,"height_MoM height.%d\n",height);
    MoM = safecoin_calcMoM(height,MoMdepth);
    ret.push_back(Pair("coin",(char *)(ASSETCHAINS_SYMBOL[0] == '\0' ? "SAFE" : ASSETCHAINS_SYMBOL)));
    ret.push_back(Pair("height",height));
    ret.push_back(Pair("MoMdepth",MoMdepth));
    ret.push_back(Pair("MoM",MoM.GetHex()));
    return ret;
}


UniValue migrate_converttoexport(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "migrate_converttoexport rawTx dest_symbol export_amount\n"
            "\nConvert a raw transaction to a cross-chain export.\n"
            "If neccesary, the transaction should be funded using fundrawtransaction.\n"
            "Finally, the transaction should be signed using signrawtransaction\n"
            "The finished export transaction, plus the payouts, should be passed to "
            "the \"migrate_createimporttransaction\" method on a SAFE node to get the corresponding "
            "import transaction.\n"
            );

    if (ASSETCHAINS_CC < SAFECOIN_FIRSTFUNGIBLEID)
        throw runtime_error("-ac_cc < SAFECOIN_FIRSTFUNGIBLEID");

    if (ASSETCHAINS_SYMBOL[0] == '\0')
        throw runtime_error("Must be called on assetchain");

    vector<uint8_t> txData(ParseHexV(params[0], "argument 1"));
    CMutableTransaction tx;
    if (!E_UNMARSHAL(txData, ss >> tx))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    string targetSymbol = params[1].get_str();
    if (targetSymbol.size() == 0 || targetSymbol.size() > 32)
        throw runtime_error("targetSymbol length must be >0 and <=32");

    CAmount burnAmount = AmountFromValue(params[2]);
    if (burnAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for export");
    {
        CAmount needed = 0;
        for (auto out : tx.vout)
            needed += out.nValue;
        if (burnAmount < needed)
            throw runtime_error("export_amount too small");
    }

    CTxOut burnOut = MakeBurnOutput(burnAmount, ASSETCHAINS_CC, targetSymbol, tx.vout);
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("payouts", HexStr(E_MARSHAL(ss << tx.vout))));
    tx.vout.clear();
    tx.vout.push_back(burnOut);
    ret.push_back(Pair("exportTx", HexStr(E_MARSHAL(ss << tx))));
    return ret;
}


/*
 * The process to migrate funds
 *
 * Create a transaction on assetchain:
 *
 * generaterawtransaction
 * migrate_converttoexport
 * fundrawtransaction
 * signrawtransaction
 *
 * migrate_createimportransaction
 * migrate_completeimporttransaction
 */

UniValue migrate_createimporttransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error("migrate_createimporttransaction burnTx payouts\n\n"
                "Create an importTx given a burnTx and the corresponding payouts, hex encoded");

    if (ASSETCHAINS_CC < SAFECOIN_FIRSTFUNGIBLEID)
        throw runtime_error("-ac_cc < SAFECOIN_FIRSTFUNGIBLEID");

    if (ASSETCHAINS_SYMBOL[0] == '\0')
        throw runtime_error("Must be called on assetchain");

    vector<uint8_t> txData(ParseHexV(params[0], "argument 1"));

    CTransaction burnTx;
    if (!E_UNMARSHAL(txData, ss >> burnTx))
        throw runtime_error("Couldn't parse burnTx");


    vector<CTxOut> payouts;
    if (!E_UNMARSHAL(ParseHexV(params[1], "argument 2"), ss >> payouts))
        throw runtime_error("Couldn't parse payouts");

    uint256 txid = burnTx.GetHash();
    TxProof proof = GetAssetchainProof(burnTx.GetHash());

    CTransaction importTx = MakeImportCoinTransaction(proof, burnTx, payouts);
    return HexStr(E_MARSHAL(ss << importTx));
}


UniValue migrate_completeimporttransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error("migrate_completeimporttransaction importTx\n\n"
                "Takes a cross chain import tx with proof generated on assetchain "
                "and extends proof to target chain proof root");

    if (ASSETCHAINS_SYMBOL[0] != '\0')
        throw runtime_error("Must be called on SAFE");

    CTransaction importTx;
    if (!E_UNMARSHAL(ParseHexV(params[0], "argument 1"), ss >> importTx))
        throw runtime_error("Couldn't parse importTx");

    CompleteImportTransaction(importTx);

    return HexStr(E_MARSHAL(ss << importTx));
}


UniValue getNotarisationsForBlock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error("getNotarisationsForBlock blockHash\n\n"
                "Takes a block hash and returns notarisation transactions "
                "within the block");

    uint256 blockHash = uint256S(params[0].get_str());

    NotarisationsInBlock nibs;
    GetBlockNotarisations(blockHash, nibs);
    UniValue out(UniValue::VARR);
    for (const Notarisation& n : nibs)
    {
        UniValue item(UniValue::VARR);
        item.push_back(n.first.GetHex());
        item.push_back(HexStr(E_MARSHAL(ss << n.second)));
        out.push_back(item);
    }
    return out;
}


UniValue scanNotarisationsDB(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error("scanNotarisationsDB blockHeight symbol [blocksLimit=1440]\n\n"
                "Scans notarisationsdb backwards from height for a notarisation"
                " of given symbol");
    int height = atoi(params[0].get_str().c_str());
    std::string symbol = params[1].get_str().c_str();

    int limit = 1440;
    if (params.size() > 2)
        limit = atoi(params[2].get_str().c_str());

    if (height == 0)
        height = chainActive.Height();

    Notarisation nota;
    int matchedHeight = ScanNotarisationsDB(height, symbol, limit, nota);
    if (!matchedHeight) return NullUniValue;
    UniValue out(UniValue::VOBJ);
    out.pushKV("height", matchedHeight);
    out.pushKV("hash", nota.first.GetHex());
    out.pushKV("opreturn", HexStr(E_MARSHAL(ss << nota.second)));
    return out;
}
