// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "base58.h"

using namespace std;

#include "chainparamsseeds.h"



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
extern uint16_t ASSETCHAINS_PORT;
extern uint32_t ASSETCHAIN_INIT;
extern uint32_t ASSETCHAINS_MAGIC;
extern uint64_t ASSETCHAINS_SUPPLY;

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams()
    {
        strNetworkID = "main";
        strCurrencyUnits = "SAFE";
        consensus.fCoinbaseMustBeProtected = false;//true;
        consensus.nSubsidySlowStartInterval = 20000;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false; //false;  //sc was true
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
         pchMessageStart[0] = 0xf1;
         pchMessageStart[1] = 0xed;
         pchMessageStart[2] = 0xe2;
         pchMessageStart[3] = 0x8f;
        vAlertPubKey = ParseHex("041d514dbd2284abacfdeaa5df43a352677820108740f45723011d4cc2bf0fd7e8b0dd524233492f88e0131bb10facf4af9f670ee9f005221a0c03f4fcae0788a6");
        nDefaultPort = 8770;
        nMinerThreads = 0;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 10000;   //sc  pruning is a good thing
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        const char* pszTimestamp = "CNN 2017/02/07 Internet rights advocate John Perry Barlow dies";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0;   //sc   originally   50 * COIN
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("0479db7ca0688048fe54fc888fa35250fdb01d7a0dd4e266183f0d76cc5925e4c17e9479c16d2ead7c626b85f8c89bbea5dd995caf0dbd0ef80cd243bdecadb8dc") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1518052105;
        genesis.nBits    = SAFECOIN_MINDIFF_NBITS;
        genesis.nNonce   = uint256S("0x0000000000000000000000000000000000000000000000000000000000000005");
        genesis.nSolution = ParseHex("0044903c8445a3365402c303313148464ff8378a6811bf9141ebea3fb3bbbb63102ce57578d3327a14772a490d5c10cb6aafc2da74d7393d2aeab88fd6c6db59bf7d5101e2012378bf08abb85d6ae690a8b5746605427bb29a4e5802d0818786def245e2afacfc7b7805b7d562a98c00e6675e939876ef4725b5d0513d4308a52247c157f9d7b22936f31f739b7ef31899f8c46f5c5de51ee4bb812c9877a58c47defef5df1edaf70257d51f4201dee68944a4af2dbab1a31ee7b9f4f105b25e8f2a49562ff848b1b37f1349b46ff0882264124c77042ae4f045d5b023311d597d6a73df95f22b1a54de2c84ce42f8b4cba87bc270d372955cb630a7025994591e518769f24002627a2da94d4e7dd657c50a9f26a27411e172aa0931216b8dd2f9423f6a34280d6fc6a177e999a5cc6a6191a37a1994d6df0c4d761e9c1699d08e9ef6a899122454bf6608c1bfa7580e029ef109b7dea8d6f64480b963ac6bb0809879821804a075e2b9cc4ee89513e339415d01592aa6518734067fbb646ce6fb1bd0f3d5f488e2eaa6ff1ebb40ac18efad699b0952b179fb47a4de432df615bf9136f7155f7a71b55a11219e48079270426275e84e373eaf1839e6e1100bd611b3c012e4a7bc4f34d1ae765d721798ffe111505ddb88402508fb383cbecdc75ec1d781d0f7c98b63e673e9d0586fcb51a5debc57b916110a76571c130ef553eded52bac6b7bd5546211a330e2ba81d7cd510650f43cdf6ec2b51a0934060bcefd4266f5407cf9fb7414ecb45fd28c65ceeb8c7dbf1455e23b6b302643f315988d626dc5f3fd5dda1940aab0ffe4d75469ad6338f7d02e8e9c8a98de35d10a32353eb6cbc39168c27322fc5bbe875c16a3ef65a1f4f14fc5e8d40521221c97db31db89f95fe453e1b6f8935782e10600f6949f92b0392197471a7a9861e59b401efd8167d95b7bd7024fadfc5dae29ed1b7f809d013585a0f0363e683a1b5237a647a4d41081c319876089ec854b7ac0edfc78368bb84e356123b98b4b19e0bfff98c85df65d9048f91b3e52a6a8145078c6f99089d2f467055c93af35012b7beeca6f8c3c332a0950f024b6730ef9975d0adc2ca4d5457d0c3755d5c5e0a1198b57317368d768da0a8f07ba750f539d13ed60cad125bbd9ad47f010331b42da654a8f24cafefc6047dd79da9c3f3b4ee7c51257613b1bb28ef9abb5e240e6e40a1a030efdf37455fce3a1c99da4a39abeb19b820e1bf8b7ff56be6153cc87a7d09c40fd07fd94f9cede8fcdb2223876c755d10511e3d69e1df91330886b938ce99d8cf73aa711ede36cd1ad69b9f4de80d1f7d8b75b2dd7bf36d453952c6e2b733e8fa7f6c0fec4981f958e18fb01171d9066f5101d2ab7090ba1d0451fefece1feba7df344de47569252ce4ca19a604ff849ae4687a8f76c151ad5542e3da3d70bd0a97155eda3b70b09489e699b347256c3d5a1ff4537f440a5431684297026b783552e65a9d1e96d2fa7b16381ca102f554ccce0d971a43299a7a86fce0fbd4e64f05dba3ccdc1ca6fcfc86a5f3d1c86bca38bc737e9a089f9cda471cfe773f37228c475c426d3c1e8c4c62139d5ae7108fac6d1810c32123f3319dca7d348a9b19a11644ab5afa9ee86b03c129c7fb29ceb09361960b6e46b249461bf88c0bd0c789201b3941935924e8103261fba0d678c17ecb8192ce0e61c736c99fdf5014a5c574c3881d9043f821fa83715ccc8845becfed7cd874ac002aa32b9bf5bbc2dafb4022f3da393cea10b54fc961ebfd8595cce476253b3d496d092b715132f821b07b1f3aef81c0a5da27ba63f1cba699ff4f1546e0b441d1a7dca5fad66675dbda72371eda8f23157e76fc4147e86576d1f53d704d099ea7515ac7dc");


        consensus.hashGenesisBlock = genesis.GetHash();
       assert(consensus.hashGenesisBlock == uint256S("0x09f5deffb9c816d82b8f696befa84681509274288c4529f213aeeac57999e8c9"));
       assert(genesis.hashMerkleRoot == uint256S("0x0e8398ad8ba699fa41e1c56fe6112ca2530719c32b7e3d0cdb6610a458bd7e14"));


       vSeeds.push_back(CDNSSeedData("107.191.36.192", "107.191.36.192")); // seed node
       vSeeds.push_back(CDNSSeedData("45.77.109.253", "45.77.109.253")); // seed node
       vSeeds.push_back(CDNSSeedData("safecoin.org", "dnsseed.safecoin.org")); // Safecoin
       vSeeds.push_back(CDNSSeedData("ipv6admin.com", "dnsseed.ipv6admin.com")); // Ipv6ipv6admin
       vSeeds.push_back(CDNSSeedData("fair.exchange", "dnsseed.fair.exchange")); // Safecoin

        // TODO: set up bootstrapping for mainnet
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,61);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,86);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,189);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1F).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE5).convert_to_container<std::vector<unsigned char> >();
        // guarantees the first two characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {21,154};
        // guarantees the first two characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY] = {171,54};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        checkpointData = (Checkpoints::CCheckpointData)
        {
            boost::assign::map_list_of
            //  (0,uint256S("0x01")),
            (0, uint256S("0x09f5deffb9c816d82b8f696befa84681509274288c4529f213aeeac57999e8c9"))
            (10000, uint256S("0x0000003fac4b19715f7c926678efa76580ec6677f00f986e6d62df24c2c33c40"))
            (20000, uint256S("0x000001abf017b27b1ed2830915b07840a03ff692130e92ea618abf7dd199bffd"))
            (30000, uint256S("0x0000020087dd554bee50fd4f2bdd267f1e05b8a8825eb6b147de9f5d708c0087"))
            (40000, uint256S("0x00000071520e510befabaee27357de84f7d624b019096693845a392b28fdc017"))
            (50000, uint256S("0x000001130278ac0759ba6edf6c046db74b5b5be14536779d9a78e67b97f7f55c"))
            (60000, uint256S("0x00000072465c9f88a415a4543be84365b036415032cebe35d7cfd247335799cd"))
            (70000, uint256S("0x00000031541bd6ea69b38450121d993cfb41663ab167fcfce47f598073dd534e"))
            (75000, uint256S("0x00000012f1f0aa4ac984d46739767d503e87087f2ad022eea22e67f2e21a6805"))
            (80000, uint256S("0x000000010f731dad693d6e60f32f504db5ffdb2e2e9793ece5f2a22dbe53ee0d"))
            (84748, uint256S("0x00000042f72109bb83060ed5c34505740fcfa5676ccfb724c38b048456ae838a")),
            //(100000, uint256S("0x0f02eb1f3a4b89df9909fec81a4bd7d023e32e24e1f5262d9fc2cc36a715be6f")),
            1523887013,     // * UNIX timestamp of last checkpoint block
            155378,         // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            2700            // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };
        if ( pthread_create((pthread_t *)malloc(sizeof(pthread_t)),NULL,chainparams_commandline,(void *)&consensus) != 0 )
        {

        }
    }
};
static CMainParams mainParams;

void *chainparams_commandline(void *ptr)
{
    while ( ASSETCHAINS_PORT == 0 )
    {
        #ifdef _WIN32
        boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
        #else
        sleep(1);
        #endif
    }
    //fprintf(stderr,">>>>>>>> port.%u\n",ASSETCHAINS_PORT);
    if ( ASSETCHAINS_SYMBOL[0] != 0 )
    {
        mainParams.SetDefaultPort(ASSETCHAINS_PORT);
        mainParams.pchMessageStart[0] = ASSETCHAINS_MAGIC & 0xff;
        mainParams.pchMessageStart[1] = (ASSETCHAINS_MAGIC >> 8) & 0xff;
        mainParams.pchMessageStart[2] = (ASSETCHAINS_MAGIC >> 16) & 0xff;
        mainParams.pchMessageStart[3] = (ASSETCHAINS_MAGIC >> 24) & 0xff;
        fprintf(stderr,">>>>>>>>>> %s: port.%u/%u magic.%08x %u %u coins\n",ASSETCHAINS_SYMBOL,ASSETCHAINS_PORT,ASSETCHAINS_PORT+1,ASSETCHAINS_MAGIC,ASSETCHAINS_MAGIC,(uint32_t)ASSETCHAINS_SUPPLY);
    }
    ASSETCHAIN_INIT = 1;
    return(0);
}

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TAZ";
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.fPowAllowMinDifficultyBlocks = true;
        pchMessageStart[0] = 0xd6;   //sc randomized
        pchMessageStart[1] = 0xb4;   //sc randomized
        pchMessageStart[2] = 0xbe;   //sc randomized
        pchMessageStart[3] = 0xf5;   //sc randomized
        vAlertPubKey = ParseHex("042bef4ddda2baded216c4c21edb76aecd246c2dba226d8058ca050eb75bcce6e0e683f8cd6b570014ad991580941e7fa86fe6ff71e11028f98abde32454fa7b7e");
        nDefaultPort = 18770;
        nMinerThreads = 0;
        nPruneAfterHeight = 1000;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1517468992;
        genesis.nBits = SAFECOIN_MINDIFF_NBITS;
        genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000009");


        genesis.nSolution = ParseHex("003423da3e41f916bf3ff0ee770eb844a240361abe08a8c9d46bd30226e2ad411a4047b6ddc230d173c60537e470e24f764120f5a2778b2a1285b0727bf79a0b085ad67e6266fb38fd72ef17f827315c42f921720248c983d4100e6ebd1c4b5e8762a973bac3bec7f7153b93752ebbb465f0fc9520bcfc30f9abfe303627338fed6ede9cf1b9173a736cf270cf4d9c6999ff4c3a301a78fd50dab6ccca67a0c5c2e41f216a1f3efd049a74bbe6252f9773bc309d3f9e554d996913ce8e1cec672a1fa4ea59726b61ea9e75d5ce9aa5dbfa96179a293810e02787f26de324fe7c88376ff57e29574a55faff7c2946f3e40e451861c32bf67da7377de3136858a18f34fab1bc8da37726ca2c25fc7b312a5427554ec944da81c7e27255d6c94ade9987ff7daedc2d1cc63d7d4cf93e691d13326fb1c7ee72ccdc0b134eb665fc6a9821e6fef6a6d45e4aac6dca6b505a0100ad56ea4f6fa4cdc2f0d1b65f730104a515172e34163bdb422f99d083e6eb860cf6b3f66642c4dbaf0d0fa1dca1b6166f1d1ffaa55a9d6d6df628afbdd14f1622c1c8303259299521a253bc28fcc93676723158067270fc710a09155a1e50c533e9b79ed5edba4ab70a08a9a2fc0eef0ddae050d75776a9804f8d6ad7e30ccb66c6a98d86710ca7a4dfb4feb159484796b9a015c5764aa3509051c87f729b9877ea41f8b470898c01388ed9098b1e006d3c30fc6e7c781072fa3f75d918505ee8ca75840fc62f67c57060666aa42578a2dd022eda62e3f1e447d7364074d34fd60ad9b138f60422afa6cfcb913fd6c213b496144dbfda7bfc7c24540cfe40ad0c0fd5a8c0902127f53d3178ba1b2a87bf1224d53d3a15e49ccdf121ae872a011c996d1b9793153cdcd4c0a7e99f8a35669788551cca2b62769eda24b6b55e2f4e0ac0d30aa50ecf33c6cdb24adfc922006a7bf434ced800fefe814c94c6fc8caa37b372d5088bb31d2f6b11a7a67ad3f70abbac0d5c256b637828de6cc525978cf151a2e50798e0c591787639a030291272c9ced3ab7d682e03f8c7db51f60163baa85315789666ea8c5cd6f789a7f4a5de4f8a9dfefce20f353cec606492fde8eab3e3b487b3a3a57434f8cf252a4b643fc125c8a5948b06744f5dc306aa587bdc85364c7488235c6edddd78763675e50a9637181519be06dd30c4ba0d845f9ba320d01706fd6dd64d1aa3cd4211a4a7d1d3f2c1ef2766d27d5d2cdf8e7f5e3ea309d4f149bb737305df1373a7f5313abe5986f4aa620bec4b0065d48aafac3631de3771f5c4d2f6eec67b09d9c70a3c1969fecdb014cb3c69832b63cc9d6efa378bff0ef95ffacdeb1675bb326e698f022c1a3a2e1c2b0f05e1492a6d2b7552388eca7ee8a2467ef5d4207f65d4e2ae7e33f13eb473954f249d7c20158ae703e1accddd4ea899f026618695ed2949715678a32a153df32c08922fafad68b1895e3b10e143e712940104b3b352369f4fe79bd1f1dbe03ea9909dbcf5862d1f15b3d1557a6191f54c891513cdb3c729bb9ab08c0d4c35a3ed67d517ffe1e2b7a798521aed15ff9822169c0ec860d7b897340bc2ef4c37f7eb73bd7dafef12c4fd4e6f5dd3690305257ae14ed03df5e3327b68467775a90993e613173fa6650ffa2a26e84b3ce79606bf234eda9f4053307f344099e3b10308d3785b8726fd02d8e94c2759bebd05748c3fe7d5fe087dc63608fb77f29708ab167a13f32da251e249a544124ed50c270cfc6986d9d1814273d2f0510d0d2ea335817207db6a4a23ae9b079967b63b25cb3ceea7001b65b879263f5009ac84ab89738a5b8b71fd032beb9f297326f1f5afa630a5198d684514e242f315a4d95fa6802e82799a525bb653b80b4518ec610a5996403b1391");
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38"));

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("z.cash", "dns.testnet.z.cash")); // Safecoin

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {20,81};
        base58Prefixes[ZCSPENDING_KEY] = {177,235};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        //fRequireRPCPassword = true;
        fMiningRequiresPeers = false;//true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            (0, uint256S("0x001")),
            //(2500, uint256S("0x0e6a3d5a46eba97c4e7618d66a39f115729e1176433c98481124c2bf733aa54e"))
            //(15000, uint256S("0x00f0bd236790e903321a2d22f85bd6bf8a505f6ef4eddb20458a65d37e14d142")),
            //(100000, uint256S("0x0f02eb1f3a4b89df9909fec81a4bd7d023e32e24e1f5262d9fc2cc36a715be6f")),
            1517468992,     // * UNIX timestamp of last checkpoint block
            0,         // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            250            // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        consensus.fCoinbaseMustBeProtected = true;   //from zencash
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        pchMessageStart[0] = 0xd5;   //sc randomized
        pchMessageStart[1] = 0xb3;   //sc randomized
        pchMessageStart[2] = 0xb8;   //sc randomized
        pchMessageStart[3] = 0xf4;   //sc randomized
        nMinerThreads = 1;
        nMaxTipAge = 24 * 60 * 60;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        genesis.nTime = 1296688602;
        genesis.nBits = SAFECOIN_MINDIFF_NBITS;
        genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000021");


        genesis.nSolution = ParseHex("0f2a976db4c4263da10fd5d38eb1790469cf19bdb4bf93450e09a72fdff17a3454326399");
        consensus.hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 17779;
//sc        assert(consensus.hashGenesisBlock == uint256S("0x00a215b4fe36f5d2f829d43e587bf10e89e64f9f48a5b6ce18559089e8fd643d"));
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (Checkpoints::CCheckpointData){
            boost::assign::map_list_of
            (0, uint256S("0x001")),
            //(2500, uint256S("0x0e6a3d5a46eba97c4e7618d66a39f115729e1176433c98481124c2bf733aa54e"))
            //(15000, uint256S("0x00f0bd236790e903321a2d22f85bd6bf8a505f6ef4eddb20458a65d37e14d142")),
            //(100000, uint256S("0x0f02eb1f3a4b89df9909fec81a4bd7d023e32e24e1f5262d9fc2cc36a715be6f")),
            1517468992,     // * UNIX timestamp of last checkpoint block
            0,         // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            0            // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = { "RgLe53PKXUqyG5zm7hjspETW2imMyYFDPv" };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
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

    CBitcoinAddress address(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(address.IsValid());
    assert(address.IsScript());
    CScriptID scriptID = get<CScriptID>(address.Get()); // Get() returns a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}
