// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'Zcash' + blake2s(b'The Economist 2016-10-29 Known unknown: Another crypto-currency is born. BTC#436254 0000000000000000044f321997f336d2908cf8c8d6893e88dbf067e2d949487d ETH#2521903 483039a6b6bd8bd05f0584f9a078d075e454925eb71c1f13eaff59b405a721bb DJIA close on 27 Oct 2016: 18,169.68').hexdigest()
 *
 * CBlock(hash=00040fe8, ver=4, hashPrevBlock=00000000000000, hashMerkleRoot=c4eaa5, nTime=1477641360, nBits=1f07ffff, nNonce=4695, vtx=1)
 *   CTransaction(hash=c4eaa5, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334)
 *     CTxOut(nValue=0.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: c4eaa5
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Zcash0b9c4eef8b7cc417ee5001e3500984b6fea35683a7cac141a043c42064835d34";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
void *chainparams_commandline(void *ptr);
#include "safecoin_defs.h"

extern char ASSETCHAINS_SYMBOL[SAFECOIN_ASSETCHAIN_MAXLEN];
extern uint16_t ASSETCHAINS_P2PPORT,ASSETCHAINS_RPCPORT;
extern uint32_t ASSETCHAIN_INIT, ASSETCHAINS_MAGIC;
extern int32_t ASSETCHAINS_SAPLING, ASSETCHAINS_OVERWINTER;
extern uint64_t ASSETCHAINS_SUPPLY, ASSETCHAINS_ALGO, ASSETCHAINS_EQUIHASH;

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams()
    {

        strNetworkID = "main";
        strCurrencyUnits = "SAFE";
        bip44CoinType = 141; // As registered in https://github.com/satoshilabs/slips/blob/master/slip-0044.md 

        consensus.fCoinbaseMustBeProtected = false; // true this is only true wuth Verus and enforced after block 12800
        consensus.nSubsidySlowStartInterval = 20000;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.powAlternate = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 17;
        consensus.nMaxFutureBlockTime = 7 * 60; // 7 mins

        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170005;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000281b32ff3198a1");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
	std::string psztimestmp("CNN 2018/02/07 Internet rights advocate John Perry Barlow dies");
        pchMessageStart[0] = 0xf1;
        pchMessageStart[1] = 0xed;
        pchMessageStart[2] = 0xe2;
        pchMessageStart[3] = 0x8f;
        vAlertPubKey = ParseHex("041d514dbd2284abacfdeaa5df43a352677820108740f45723011d4cc2bf0fd7e8b0dd524233492f88e0131bb10facf4af9f670ee9f005221a0c03f4fcae0788a6");
        nDefaultPort = 8770;
        nMinerThreads = 0;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 10000;
        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_3 = eh192_7;
        eh_epoch_1_endblock = 175374;
        eh_epoch_2_startblock = 175344;
        eh_epoch_2_endblock = 555000;
        eh_epoch_3_startblock = 555120;


        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
	const char* pszTimestamp = psztimestmp.replace(7, 1, "7").c_str();        
	txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0;
	txNew.vout[0].scriptPubKey = CScript() << ParseHex("0479db7ca0688048fe54fc888fa35250fdb01d7a0dd4e266183f0d76cc5925e4c17e9479c16d2ead7c626b85f8c89bbea5dd995caf0dbd0ef80cd243bdecadb8dc") << OP_CHECKSIG;   genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1518052105;
        genesis.nBits    = SAFECOIN_MINDIFF_NBITS;
        genesis.nNonce   = uint256S("0x0000000000000000000000000000000000000000000000000000000000000005");
	genesis.nSolution = ParseHex("0044903c8445a3365402c303313148464ff8378a6811bf9141ebea3fb3bbbb63102ce57578d3327a14772a490d5c10cb6aafc2da74d7393d2aeab88fd6c6db59bf7d5101e2012378bf08abb85d6ae690a8b5746605427bb29a4e5802d0818786def245e2afacfc7b7805b7d562a98c00e6675e939876ef4725b5d0513d4308a52247c157f9d7b22936f31f739b7ef31899f8c46f5c5de51ee4bb812c9877a58c47defef5df1edaf70257d51f4201dee68944a4af2dbab1a31ee7b9f4f105b25e8f2a49562ff848b1b37f1349b46ff0882264124c77042ae4f045d5b023311d597d6a73df95f22b1a54de2c84ce42f8b4cba87bc270d372955cb630a7025994591e518769f24002627a2da94d4e7dd657c50a9f26a27411e172aa0931216b8dd2f9423f6a34280d6fc6a177e999a5cc6a6191a37a1994d6df0c4d761e9c1699d08e9ef6a899122454bf6608c1bfa7580e029ef109b7dea8d6f64480b963ac6bb0809879821804a075e2b9cc4ee89513e339415d01592aa6518734067fbb646ce6fb1bd0f3d5f488e2eaa6ff1ebb40ac18efad699b0952b179fb47a4de432df615bf9136f7155f7a71b55a11219e48079270426275e84e373eaf1839e6e1100bd611b3c012e4a7bc4f34d1ae765d721798ffe111505ddb88402508fb383cbecdc75ec1d781d0f7c98b63e673e9d0586fcb51a5debc57b916110a76571c130ef553eded52bac6b7bd5546211a330e2ba81d7cd510650f43cdf6ec2b51a0934060bcefd4266f5407cf9fb7414ecb45fd28c65ceeb8c7dbf1455e23b6b302643f315988d626dc5f3fd5dda1940aab0ffe4d75469ad6338f7d02e8e9c8a98de35d10a32353eb6cbc39168c27322fc5bbe875c16a3ef65a1f4f14fc5e8d40521221c97db31db89f95fe453e1b6f8935782e10600f6949f92b0392197471a7a9861e59b401efd8167d95b7bd7024fadfc5dae29ed1b7f809d013585a0f0363e683a1b5237a647a4d41081c319876089ec854b7ac0edfc78368bb84e356123b98b4b19e0bfff98c85df65d9048f91b3e52a6a8145078c6f99089d2f467055c93af35012b7beeca6f8c3c332a0950f024b6730ef9975d0adc2ca4d5457d0c3755d5c5e0a1198b57317368d768da0a8f07ba750f539d13ed60cad125bbd9ad47f010331b42da654a8f24cafefc6047dd79da9c3f3b4ee7c51257613b1bb28ef9abb5e240e6e40a1a030efdf37455fce3a1c99da4a39abeb19b820e1bf8b7ff56be6153cc87a7d09c40fd07fd94f9cede8fcdb2223876c755d10511e3d69e1df91330886b938ce99d8cf73aa711ede36cd1ad69b9f4de80d1f7d8b75b2dd7bf36d453952c6e2b733e8fa7f6c0fec4981f958e18fb01171d9066f5101d2ab7090ba1d0451fefece1feba7df344de47569252ce4ca19a604ff849ae4687a8f76c151ad5542e3da3d70bd0a97155eda3b70b09489e699b347256c3d5a1ff4537f440a5431684297026b783552e65a9d1e96d2fa7b16381ca102f554ccce0d971a43299a7a86fce0fbd4e64f05dba3ccdc1ca6fcfc86a5f3d1c86bca38bc737e9a089f9cda471cfe773f37228c475c426d3c1e8c4c62139d5ae7108fac6d1810c32123f3319dca7d348a9b19a11644ab5afa9ee86b03c129c7fb29ceb09361960b6e46b249461bf88c0bd0c789201b3941935924e8103261fba0d678c17ecb8192ce0e61c736c99fdf5014a5c574c3881d9043f821fa83715ccc8845becfed7cd874ac002aa32b9bf5bbc2dafb4022f3da393cea10b54fc961ebfd8595cce476253b3d496d092b715132f821b07b1f3aef81c0a5da27ba63f1cba699ff4f1546e0b441d1a7dca5fad66675dbda72371eda8f23157e76fc4147e86576d1f53d704d099ea7515ac7dc");



        /*genesis = CreateGenesisBlock(
            1477641360,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000001257"),
            ParseHex("000a889f00854b8665cd555f4656f68179d31ccadc1b1f7fb0952726313b16941da348284d67add4686121d4e3d930160c1348d8191c25f12b267a6a9c131b5031cbf8af1f79c9d513076a216ec87ed045fa966e01214ed83ca02dc1797270a454720d3206ac7d931a0a680c5c5e099057592570ca9bdf6058343958b31901fce1a15a4f38fd347750912e14004c73dfe588b903b6c03166582eeaf30529b14072a7b3079e3a684601b9b3024054201f7440b0ee9eb1a7120ff43f713735494aa27b1f8bab60d7f398bca14f6abb2adbf29b04099121438a7974b078a11635b594e9170f1086140b4173822dd697894483e1c6b4e8b8dcd5cb12ca4903bc61e108871d4d915a9093c18ac9b02b6716ce1013ca2c1174e319c1a570215bc9ab5f7564765f7be20524dc3fdf8aa356fd94d445e05ab165ad8bb4a0db096c097618c81098f91443c719416d39837af6de85015dca0de89462b1d8386758b2cf8a99e00953b308032ae44c35e05eb71842922eb69797f68813b59caf266cb6c213569ae3280505421a7e3a0a37fdf8e2ea354fc5422816655394a9454bac542a9298f176e211020d63dee6852c40de02267e2fc9d5e1ff2ad9309506f02a1a71a0501b16d0d36f70cdfd8de78116c0c506ee0b8ddfdeb561acadf31746b5a9dd32c21930884397fb1682164cb565cc14e089d66635a32618f7eb05fe05082b8a3fae620571660a6b89886eac53dec109d7cbb6930ca698a168f301a950be152da1be2b9e07516995e20baceebecb5579d7cdbc16d09f3a50cb3c7dffe33f26686d4ff3f8946ee6475e98cf7b3cf9062b6966e838f865ff3de5fb064a37a21da7bb8dfd2501a29e184f207caaba364f36f2329a77515dcb710e29ffbf73e2bbd773fab1f9a6b005567affff605c132e4e4dd69f36bd201005458cfbd2c658701eb2a700251cefd886b1e674ae816d3f719bac64be649c172ba27a4fd55947d95d53ba4cbc73de97b8af5ed4840b659370c556e7376457f51e5ebb66018849923db82c1c9a819f173cccdb8f3324b239609a300018d0fb094adf5bd7cbb3834c69e6d0b3798065c525b20f040e965e1a161af78ff7561cd874f5f1b75aa0bc77f720589e1b810f831eac5073e6dd46d00a2793f70f7427f0f798f2f53a67e615e65d356e66fe40609a958a05edb4c175bcc383ea0530e67ddbe479a898943c6e3074c6fcc252d6014de3a3d292b03f0d88d312fe221be7be7e3c59d07fa0f2f4029e364f1f355c5d01fa53770d0cd76d82bf7e60f6903bc1beb772e6fde4a70be51d9c7e03c8d6d8dfb361a234ba47c470fe630820bbd920715621b9fbedb49fcee165ead0875e6c2b1af16f50b5d6140cc981122fcbcf7c5a4e3772b3661b628e08380abc545957e59f634705b1bbde2f0b4e055a5ec5676d859be77e20962b645e051a880fddb0180b4555789e1f9344a436a84dc5579e2553f1e5fb0a599c137be36cabbed0319831fea3fddf94ddc7971e4bcf02cdc93294a9aab3e3b13e3b058235b4f4ec06ba4ceaa49d675b4ba80716f3bc6976b1fbf9c8bf1f3e3a4dc1cd83ef9cf816667fb94f1e923ff63fef072e6a19321e4812f96cb0ffa864da50ad74deb76917a336f31dce03ed5f0303aad5e6a83634f9fcc371096f8288b8f02ddded5ff1bb9d49331e4a84dbe1543164438fde9ad71dab024779dcdde0b6602b5ae0a6265c14b94edd83b37403f4b78fcd2ed555b596402c28ee81d87a909c4e8722b30c71ecdd861b05f61f8b1231795c76adba2fdefa451b283a5d527955b9f3de1b9828e7b2e74123dd47062ddcc09b05e7fa13cb2212a6fdbc65d7e852cec463ec6fd929f5b8483cf3052113b13dac91b69f49d1b7d1aec01c4a68e41ce157"),
            0x1f07ffff, 4, 0);*/

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x09f5deffb9c816d82b8f696befa84681509274288c4529f213aeeac57999e8c9"));
        assert(genesis.hashMerkleRoot == uint256S("0x0e8398ad8ba699fa41e1c56fe6112ca2530719c32b7e3d0cdb6610a458bd7e14"));
        vFixedSeeds.clear();
        vSeeds.clear();
        //Disabled until dnsseder is updated to support TLS connections.
        //vSeeds.push_back(CDNSSeedData("dnsseed2", "dnsseedua.local.support"));		// OleksandrBlack
	//End Disabled
        vSeeds.push_back(CDNSSeedData("dnsseed3", "dnsseed.local.support"));
        vSeeds.push_back(CDNSSeedData("dnsseed4", "dnsseed.fair.exchange"));
        vSeeds.push_back(CDNSSeedData("explorer", "explorer.safecoin.org"));
        // TODO: set up bootstrapping for mainnet
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,61);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,86);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,189);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1F).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE5).convert_to_container<std::vector<unsigned char> >();
        // guarantees the first two characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {21,154};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first two characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY] = {171,54};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        if ( pthread_create((pthread_t *)malloc(sizeof(pthread_t)),NULL,chainparams_commandline,(void *)&consensus) != 0 )
        {

        }
    }
};

static CMainParams mainParams;

void CChainParams::SetCheckpointData(CChainParams::CCheckpointData checkpointData)
{
    CChainParams::checkpointData = checkpointData;
}

int32_t MAX_BLOCK_SIZE(int32_t height)
{
    //fprintf(stderr,"MAX_BLOCK_SIZE %d vs. %d\n",height,mainParams.consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight);
    if ( height <= 0 || (mainParams.consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight > 0 && height >= mainParams.consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight) )
        return(4096 * 1024);
    else return(2000000);
}

void safecoin_setactivation(int32_t height)
{
    mainParams.consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = height;
    mainParams.consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = height;
    ASSETCHAINS_SAPLING = height;
    fprintf(stderr,"SET SAPLING ACTIVATION height.%d\n",height);
}

void *chainparams_commandline(void *ptr)
{
    CChainParams::CCheckpointData checkpointData;
    while ( ASSETCHAINS_P2PPORT == 0 )
    {
        #ifdef _WIN32
        boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
        #else
        sleep(1);
        #endif
    }
    //fprintf(stderr,">>>>>>>> port.%u\n",ASSETCHAINS_P2PPORT);
    if ( ASSETCHAINS_SYMBOL[0] != 0 )
    {
        mainParams.SetDefaultPort(ASSETCHAINS_P2PPORT);
        if ( ASSETCHAINS_RPCPORT == 0 )
            ASSETCHAINS_RPCPORT = ASSETCHAINS_P2PPORT + 1;
        mainParams.pchMessageStart[0] = ASSETCHAINS_MAGIC & 0xff;
        mainParams.pchMessageStart[1] = (ASSETCHAINS_MAGIC >> 8) & 0xff;
        mainParams.pchMessageStart[2] = (ASSETCHAINS_MAGIC >> 16) & 0xff;
        mainParams.pchMessageStart[3] = (ASSETCHAINS_MAGIC >> 24) & 0xff;
        fprintf(stderr,">>>>>>>>>> %s: p2p.%u rpc.%u magic.%08x %u %u coins\n",ASSETCHAINS_SYMBOL,ASSETCHAINS_P2PPORT,ASSETCHAINS_RPCPORT,ASSETCHAINS_MAGIC,ASSETCHAINS_MAGIC,(uint32_t)ASSETCHAINS_SUPPLY);

        if (ASSETCHAINS_ALGO != ASSETCHAINS_EQUIHASH)
        {
            // this is only good for 60 second blocks with an averaging window of 45. for other parameters, use:
            // nLwmaAjustedWeight = (N+1)/2 * (0.9989^(500/nPowAveragingWindow)) * nPowTargetSpacing 
            mainParams.consensus.nLwmaAjustedWeight = 1350;
            mainParams.consensus.nPowAveragingWindow = 45;
            mainParams.consensus.powAlternate = uint256S("00000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        }


        // only require coinbase protection on Verus from the Safecoin family of coins
        if (strcmp(ASSETCHAINS_SYMBOL,"VRSC") == 0)
        {
            mainParams.consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 227520;
            mainParams.consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 227520;
            mainParams.consensus.fCoinbaseMustBeProtected = true;
            checkpointData = //(Checkpoints::CCheckpointData)
                {
                    boost::assign::map_list_of
                    (0, mainParams.consensus.hashGenesisBlock),
                //(2500, uint256S("0x0e6a3d5a46eba97c4e7618d66a39f115729e1176433c98481124c2bf733aa54e"))
                //(15000, uint256S("0x00f0bd236790e903321a2d22f85bd6bf8a505f6ef4eddb20458a65d37e14d142")),
                //(100000, uint256S("0x0f02eb1f3a4b89df9909fec81a4bd7d023e32e24e1f5262d9fc2cc36a715be6f")),
                (int64_t)1481120910,     // * UNIX timestamp of last checkpoint block
                (int64_t)110415,         // * total number of transactions between genesis and last checkpoint
                                //   (the tx=... number in the SetBestChain debug.log lines)
                (double)2777            // * estimated number of transactions per day after checkpoint
                                            //   total number of tx / (checkpoint block height / (24 * 24))
                };

            mainParams.consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000001a8f4f23f8b2d1f7e");
        }
        else
        {
            if (strcmp(ASSETCHAINS_SYMBOL,"VRSCTEST") == 0 || strcmp(ASSETCHAINS_SYMBOL,"VERUSTEST") == 0)
            {
                mainParams.consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000001f7e");
            }
            mainParams.consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = ASSETCHAINS_SAPLING;
            mainParams.consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = ASSETCHAINS_OVERWINTER;
            checkpointData = //(Checkpoints::CCheckpointData)
                {
                    boost::assign::map_list_of
                    (0, mainParams.consensus.hashGenesisBlock),
                    (int64_t)1481120910,
                    (int64_t)110415,
                    (double)2777            // * estimated number of transactions per day after checkpoint
                                            //   total number of tx / (checkpoint block height / (24 * 24))
                };
        }
    }
    else
    {
            checkpointData = //(Checkpoints::CCheckpointData)
            {
                boost::assign::map_list_of
                (0, mainParams.consensus.hashGenesisBlock)
				(10000, uint256S("0x0000003fac4b19715f7c926678efa76580ec6677f00f986e6d62df24c2c33c40"))
				(20000, uint256S("0x000001abf017b27b1ed2830915b07840a03ff692130e92ea618abf7dd199bffd"))
				(30000, uint256S("0x0000020087dd554bee50fd4f2bdd267f1e05b8a8825eb6b147de9f5d708c0087"))
				(40000, uint256S("0x00000071520e510befabaee27357de84f7d624b019096693845a392b28fdc017"))
				(50000, uint256S("0x000001130278ac0759ba6edf6c046db74b5b5be14536779d9a78e67b97f7f55c"))
				(60000, uint256S("0x00000072465c9f88a415a4543be84365b036415032cebe35d7cfd247335799cd"))
				(70000, uint256S("0x00000031541bd6ea69b38450121d993cfb41663ab167fcfce47f598073dd534e"))
				(75000, uint256S("0x00000012f1f0aa4ac984d46739767d503e87087f2ad022eea22e67f2e21a6805"))
				(80000, uint256S("0x000000010f731dad693d6e60f32f504db5ffdb2e2e9793ece5f2a22dbe53ee0d"))
				(84748, uint256S("0x00000042f72109bb83060ed5c34505740fcfa5676ccfb724c38b048456ae838a"))
				(102864, uint256S("0x00000025561af0c339a1df438fee5ccfa7c49bfcfdcb4d070b0d96cb429bedb5"))
				(170242, uint256S("0x00000011069f756ed14d4967b9862331ebb2f41a2928291066981258adc672d5"))	//switch to equihash 144,5
				(360000, uint256S("0x00000260ec5c16afbc1d4e70f9616e60bbc3222ad3604c0d2acdf716da7f8b9c"))
				(420000, uint256S("0x000002f4a612958896c215e9541a3036fd0401377c03e00d5a5e9fb3dbd379a4"))       //add TLS
				(469630, uint256S("0x000001712c534cca9aca4fac0cf565557ddd8a60ae60b1b8a66f16a0072d608a")),       			
				(int64_t)1547217229,	// * UNIX timestamp of last checkpoint block
				(int64_t)814979,		// * total number of transactions between genesis and last checkpoint
										//   (the tx=... number in the SetBestChain debug.log lines)
				(double)1000			// * estimated number of transactions per day after checkpoint
										//   total number of tx / (checkpoint block height / (24 * 24))
		};
    }

    mainParams.SetCheckpointData(checkpointData);

    ASSETCHAIN_INIT = 1;
    return(0);
}

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TAZ";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 20000;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.powAlternate = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nMaxFutureBlockTime = 7 * 60;

        vAlertPubKey = ParseHex("00");
        nDefaultPort = 18770;
        nMinerThreads = 0;
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 299187;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 207500;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 280000;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000000001d0c4d9cd");

        pchMessageStart[0] = 0x5A;
        pchMessageStart[1] = 0x1F;
        pchMessageStart[2] = 0x7E;
        pchMessageStart[3] = 0x62;
        vAlertPubKey = ParseHex("020e46e79a2a8d12b9b5d12c7a91adb4e454edfae43c0a0cb805427d2ac7613fd9");
        nMaxTipAge = 24 * 60 * 60;

        nPruneAfterHeight = 1000;
        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_3 = eh192_7;
        eh_epoch_1_endblock = 10;
        eh_epoch_2_startblock = 30;
        eh_epoch_2_endblock = 40;
        eh_epoch_3_startblock = 50;


         const char* pszTimestamp = "CNN 2018/02/07 Internet rights advocate John Perry Barlow dies";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0;
	txNew.vout[0].scriptPubKey = CScript() << ParseHex("0479db7ca0688048fe54fc888fa35250fdb01d7a0dd4e266183f0d76cc5925e4c17e9479c16d2ead7c626b85f8c89bbea5dd995caf0dbd0ef80cd243bdecadb8dc") << OP_CHECKSIG;   genesis.vtx.push_back(txNew);
  

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
	genesis.hashMerkleRoot = genesis.BuildMerkleTree();
	genesis.hashPrevBlock.SetNull();
	genesis.nVersion = 1;
        genesis.nTime = 1525561967;
        genesis.nBits = SAFECOIN_MINDIFF_NBITS;
        genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000016");
        genesis.nSolution = ParseHex("002802873b511a44c841a1a1ae62f7e06bf855bbb11f097ff4a313a710e20583021daed00eeed8badcff06be5fea6f4228ad065101233b151088f2ce78ee4e13fbe2378f8dc3daf7f7d228d6c5a1dd7546d4fe57129185b02f16be06dc4612b6d126b4658ee8176b81206242114d643a4181b242d999b6ad21439d1e4090205754aeb38d260ac7de55f57b31a0f1b4e89c68cb366de9df5adab683e6158b131ce2d232ca135c3f930510bc4bf083fee4c0d7e4ca17aca42f4f599ef6661dc2b2ae50b47021af0f253519c23f1e908ff93f581638730c891fba8554468b58eee2a8f310973c01bf57016c69ced67b6f313ef6163ed1cba1bdcd98a29205c76e8faa1038dada51d17aabd06271c0cc7669d13aa2df129a0ec2c3dc3896246cbe6cda1350d9736407145a16fe5620cda37d2143ec5efe5a155218125c16644ba9464f8c73a7794320aba9f8d1c3ac785be101e82e6579d759bac46cd7cbfde3ee2b2558fff78729e80717456fd36d899f296906f0dd5e60c89706b82c8e716ee42d25c9e4b725fe99c3801600f7f5264d5c74666bbb9adc2f9d62b8496fccf2d68a677c1c120258a21687d6d648e3b130b155b34df6c42d1b911510e3688ebf2013dde02ca70cb55f108ae1cdbcb9011f814d69714d80e7c9003b441cfa0d43a6901d796124602446caa751bf710412c74de642febc489c5fda1313b93bd90aa5cebc3b03c77d5b965726bdfa5a711c9cb2689e4befc757ca32f925d5d5e7061b3d46011a3709f07114b701124a81c7109d74f078119eafef20cdbab915268e99ed93937058b0c0ae1f26d87e4a14285c7aa64dcb0d6aaf247f4a563fe984cc5a1f3c5393078fc81f07fd13a2c619dfefaee1a1c53caea721e7cbc6644fe835008c830c8ad690016c882d26e36b7a83d667db1bc5d624680d8851befb0bddbcc7a3004af22db615430b481e30ce8ce2c5ea5f7cbe20fa0736ae1ccf87e331f77c612e28760e598453b639753e9e168b0d596925845be4ba3142d811ddc7f3c360705805ae0a6f76f7a453f9516a6c039f28e4bca6da00bee99823042df96bd5045282efda3524fb89cf5c08b301e08ec46a679c6b719a1f965500ee6afa24d40a9dcfa79403169e8392719b687a0bae5f23b8e2a8538d7c6c0922c2011b9bf5a552d89ffdca502e624b037ba97e6feef427bf9b454433c5241b44701dedc5293c0ad7183034c3c385e47dcadcdb825b49f6073f2fd1c7d04ea2d2fbc6e5137ebb5c32f931235a144640ae16c797d543936519f494543f591950310de3521166ef87524ccebb23c3d4251a5da589095e1065082c3b7b81e74eda84bc99777587728226a121b5947d1e1092f0eee57115fe83767b6934b6bdf5761a3fef4bd78c4d1d998bcad6a6962b52beb1a6276e9b20c1010aed1a860935bd79fdb04191bf1514f8da9f778f4128fae3171fe299221f5597a9c76e9f5204df422f04c8d6229641892f534ab6dd46730486aee69a02c408db16a70f1d328dd69e261cdab6ed32141073fea80d63d26c945489abcc54077369dd498285825d077b38241f3a7b66f6f16dd0e7734b7de23a50a37e034b1486375e6bce43212cad31ad1c672266d206198c272a42a7cdecb02a73c3e452b0c815b46188435ecac7056d94117e0b146c6dba54acf036792d30f1db79c514819db98f994cb3e602b5e3e53aed0a0cd1f66d8922188588c51ded134a4043ef63c368c9144a9fdeec42f0dc02799f64e7192e1481ecf7ea5199d77357b90ea18d5a78a378d7bb5c64f9074657ddb74e5b574c16b76b1bcc4b309292f069d852d897d291191e79462f2276130d170b293c5d537216a447aa76ec93ddb85478a68d6eb18309c9a6a709d97467bac5e03ad8b9");


	 consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x04ca468f5377ddd271e9ce66db999f4221066af27f2a1936deee28b4504f8b30"));
	assert(genesis.hashMerkleRoot == uint256S("0x018e41f814284434fed3ced40119a86d74e94082196f24aacff198253161abe2"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("testnode1", "45.63.13.60"));
        vSeeds.push_back(CDNSSeedData("testnode2", "176.107.179.32"));
        vSeeds.push_back(CDNSSeedData("testnode3", "185.20.184.51"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {20,81};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]  = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY] = {177,235};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        //fRequireRPCPassword = true;
        fMiningRequiresPeers = false;//true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;



        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x001")),
            0,
            0,
            0
        };
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.powAlternate = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 17;
        consensus.nMaxFutureBlockTime = 7 * 60; // 7 mins
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

      pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0x8e;
        pchMessageStart[2] = 0xf3;
        pchMessageStart[3] = 0xf5;
        nMinerThreads = 1;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 1000;
        eh_epoch_1 = eh48_5;
        eh_epoch_2 = eh48_5;
        eh_epoch_3 = eh48_5;
        eh_epoch_1_endblock = 1;
        eh_epoch_2_startblock = 1;
        eh_epoch_2_endblock = 1;
        eh_epoch_3_startblock = 1;

        genesis.nTime = 1296688602;
        genesis.nBits = SAFECOIN_MINDIFF_NBITS;
        genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000021");
        genesis.nSolution = ParseHex("0f2a976db4c4263da10fd5d38eb1790469cf19bdb4bf93450e09a72fdff17a3454326399");
        consensus.hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 17779;
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")),
            0,
            0,
            0
        };
        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,85);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,188);
        //base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        //base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        //base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = { "t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg" };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);

    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}


int validEHparameterList(EHparameters *ehparams, unsigned long blockheight, const CChainParams& params){
    //if in overlap period, there will be two valid solutions, else 1.
    //The upcoming version of EH is preferred so will always be first element
    //returns number of elements in list
    if(blockheight>=params.eh_epoch_3_start() && blockheight>params.eh_epoch_2_end()){
        ehparams[0]=params.eh_epoch_3_params();
        return 1;
    }
    if(blockheight>=params.eh_epoch_2_start() && blockheight>params.eh_epoch_1_end()){
        ehparams[0]=params.eh_epoch_2_params();
        return 1;
    }
    if(blockheight<params.eh_epoch_2_start()){
        ehparams[0]=params.eh_epoch_1_params();
        return 1;
    }
    if(blockheight<params.eh_epoch_3_start()){
    ehparams[0]=params.eh_epoch_2_params();
    ehparams[1]=params.eh_epoch_1_params();
    return 2;
    }
    ehparams[0]=params.eh_epoch_3_params();
    ehparams[1]=params.eh_epoch_2_params();
    return 2;   
}
