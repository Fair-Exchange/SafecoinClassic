#include "dbwrapper.h"
#include "notarisationdb.h"
#include "uint256.h"
#include "cc/eval.h"
#include "main.h"


NotarisationDB *pnotarisations;


NotarisationDB::NotarisationDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "notarisations", nCacheSize, fMemory, fWipe, false, 64) { }


NotarisationsInBlock ScanBlockNotarisations(const CBlock &block, int nHeight)
{
    EvalRef eval;
    NotarisationsInBlock vNotarisations;

    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        CTransaction tx = block.vtx[i];

        // Special case for TXSCL. Should prob be removed at some point.
        bool isTxscl = false;
        {
            NotarisationData data;
            isTxscl = ParseNotarisationOpReturn(tx, data) && IsTXSCL(data.symbol);
        }

        if (isTxscl || eval->CheckNotaryInputs(tx, nHeight, block.nTime)) {
            NotarisationData data;
            if (ParseNotarisationOpReturn(tx, data)) {
                vNotarisations.push_back(std::make_pair(tx.GetHash(), data));
                //printf("Parsed a notarisation for: %s, txid:%s, ccid:%i, momdepth:%i\n",
                //      data.symbol, tx.GetHash().GetHex().data(), data.ccId, data.MoMDepth);
                //if (!data.MoMoM.IsNull()) printf("MoMoM:%s\n", data.MoMoM.GetHex().data());
            }
            else
                LogPrintf("WARNING: Couldn't parse notarisation for tx: %s at height %i\n",
                        tx.GetHash().GetHex().data(), nHeight);
        }
    }
    return vNotarisations;
}

bool IsTXSCL(const char* symbol)
{
    return strlen(symbol) >= 5 && strncmp(symbol, "TXSCL", 5) == 0;
}


bool GetBlockNotarisations(uint256 blockHash, NotarisationsInBlock &nibs)
{
    return pnotarisations->Read(blockHash, nibs);
}


bool GetBackNotarisation(uint256 notarisationHash, Notarisation &n)
{
    return pnotarisations->Read(notarisationHash, n);
}


/*
 * Write an index of SAFE notarisation id -> backnotarisation
 */
void WriteBackNotarisations(const NotarisationsInBlock notarisations, CDBBatch &batch)
{
    int wrote = 0;
    for (const Notarisation &n : notarisations)
    {
        if (!n.second.txHash.IsNull()) {
            batch.Write(n.second.txHash, n);
            ++wrote;
        }
    }
}


void EraseBackNotarisations(const NotarisationsInBlock notarisations, CDBBatch &batch)
{
    for (const Notarisation &n : notarisations)
        if (!n.second.txHash.IsNull())
            batch.Erase(n.second.txHash);
}

/*
 * Scan notarisationsdb backwards for blocks containing a notarisation
 * for given symbol. Return height of matched notarisation or 0.
 */
int ScanNotarisationsDB(int height, std::string symbol, int scanLimitBlocks, Notarisation& out)
{
    if (height < 0 || height > chainActive.Height())
        return false;

    for (int i=0; i<scanLimitBlocks; i++) {
        if (i > height) break;
        NotarisationsInBlock notarisations;
        uint256 blockHash = *chainActive[height-i]->phashBlock;
        if (!GetBlockNotarisations(blockHash, notarisations))
            continue;

        for (Notarisation& nota : notarisations) {
            if (strcmp(nota.second.symbol, symbol.data()) == 0) {
                out = nota;
                return height-i;
            }
        }
    }
    return 0;
}
