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

#include "key_io.h"
#include "CCinclude.h"
#include "CCassets.h"
#include "CCfaucet.h"
#include "CCrewards.h"
#include "CCdice.h"
#include "CCauction.h"
#include "CClotto.h"
#include "CCfsm.h"
#include "CCHeir.h"
#include "CCchannels.h"
#include "CCOracles.h"
#include "CCPrices.h"
#include "CCPegs.h"
#include "CCTriggers.h"
#include "CCPayments.h"
#include "CCGateways.h"

/*
 CCcustom has most of the functions that need to be extended to create a new CC contract.

 A CC scriptPubKey can only be spent if it is properly signed and validated. By constraining the vins and vouts, it is possible to implement a variety of functionality. CC vouts have an otherwise non-standard form, but it is properly supported by the enhanced bitcoin protocol code as a "cryptoconditions" output and the same pubkey will create a different address.

 This allows creation of a special address(es) for each contract type, which has the privkey public. That allows anybody to properly sign and spend it, but with the constraints on what is allowed in the validation code, the contract functionality can be implemented.

 what needs to be done to add a new contract:
 1. add EVAL_CODE to eval.h
 2. initialize the variables in the CCinit function below
 3. write a Validate function to reject any unsanctioned usage of vin/vout
 4. make helper functions to create rawtx for RPC functions
 5. add rpc calls to rpcserver.cpp and rpcserver.h and in one of the rpc.cpp files
 6. add the new .cpp files to src/Makefile.am

 IMPORTANT: make sure that all CC inputs and CC outputs are properly accounted for and reconcile to the satoshi. The built in utxo management will enforce overall vin/vout constraints but it wont know anything about the CC constraints. That is what your Validate function needs to do.

 Generally speaking, there will be normal coins that change into CC outputs, CC outputs that go back to being normal coins, CC outputs that are spent to new CC outputs.

 Make sure both the CC coins and normal coins are preserved and follow the rules that make sense. It is a good idea to define specific roles for specific vins and vouts to reduce the complexity of validation.
 */

// to create a new CCaddr, add to rpcwallet the CCaddress and start with -pubkey= with the pubkey of the new address, with its wif already imported. set normaladdr and CChexstr. run CCaddress and it will print the privkey along with autocorrect the CCaddress. which should then update the CCaddr here

// Assets, aka Tokens
#define FUNCNAME IsAssetsInput
#define EVALCODE EVAL_ASSETS
const char *AssetsCCaddr = "";
const char *AssetsNormaladdr = "Rv9PYz9ccuimiGsEFzDgFXTZX7FeC4tkSm";
char AssetsCChexstr[67] = { "0303bf3e799ac03a0c12d3d92eb47d31cf4adead4f1bf9d8f772e0fd4236818241" };
uint8_t AssetsCCpriv[32] = {  };

#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Faucet
#define FUNCNAME IsFaucetInput
#define EVALCODE EVAL_FAUCET
const char *FaucetCCaddr = "";
const char *FaucetNormaladdr = "RwsRGmYWzANYLEZDxyJZjTfyv8oMyXpHf7";
char FaucetCChexstr[67] = { "039150a202897e3589160a4e4cfe55aaf1f5473d4e7617b43542947139fdfc5ed0" };
uint8_t FaucetCCpriv[32] = {  };

#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Rewards
#define FUNCNAME IsRewardsInput
#define EVALCODE EVAL_REWARDS
const char *RewardsCCaddr = "";
const char *RewardsNormaladdr = "RkJKrsVnJyvHWHWgZqUPzAh8bamHxDf2ns";
char RewardsCChexstr[67] = { "027d3ebf92cc49aa02997576e85d68fa0600d5324c9f9d98f7b4e9afa26305c474" };
uint8_t RewardsCCpriv[32] = {  };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Dice
#define FUNCNAME IsDiceInput
#define EVALCODE EVAL_DICE
const char *DiceCCaddr = "";
const char *DiceNormaladdr = "RcxqzNDGU1dsjorThdBgPYwph86oyFcHS7";
char DiceCChexstr[67] = { "0215f7180ff01802c1791e8a60b72c9bf7cd1d62b10cc752981cf1adc77ff39f78" };
uint8_t DiceCCpriv[32] = {  };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Lotto
#define FUNCNAME IsLottoInput
#define EVALCODE EVAL_LOTTO
const char *LottoCCaddr = "";
const char *LottoNormaladdr = "RcAvxKAd6hQrtzqZehJgTyoMek3e8nfMPg";
char LottoCChexstr[67] = { "022dde44b525690148fd0ea563b17091be421722532b53598c76b4166f56ae1fd2" };
uint8_t LottoCCpriv[32] = {  };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Finite State Machine
#define FUNCNAME IsFSMInput
#define EVALCODE EVAL_FSM
const char *FSMCCaddr = "";
const char *FSMNormaladdr = "RatJfX8AJDNaeKy4iUGg9HYFRixbsdoCb3";
char FSMCChexstr[67] = { "022dde44b525690148fd0ea563b17091be421722532b53598c76b4166f56ae1fd2" };
uint8_t FSMCCpriv[32] = { };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Auction
#define FUNCNAME IsAuctionInput
#define EVALCODE EVAL_AUCTION
const char *AuctionCCaddr = "";
const char *AuctionNormaladdr = "Rpnxshn76PFWqRLvmmFV4qR1QxmqQzGgj6";
char AuctionCChexstr[67] = { "022a78af6a5f916b07a962e7d2abb566d67edad23151c552c1230765aab73d88c5" };
uint8_t AuctionCCpriv[32] = {  };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Heir
#define FUNCNAME IsHeirInput
#define EVALCODE EVAL_HEIR
const char *HeirCCaddr = "";
const char *HeirNormaladdr = "RpytdVXJpTNKkARhuzQEsMd1QnbSBfCQug";
char HeirCChexstr[67] = { "02c180a7449e72ce775102161f9f76003eb904fef6485ef00cacb7e9c5991b2a0c" };
uint8_t HeirCCpriv[32] = { };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Channels
#define FUNCNAME IsChannelsInput
#define EVALCODE EVAL_CHANNELS
const char *ChannelsCCaddr = "";
const char *ChannelsNormaladdr = "RZdRSYExu8Wr6CQaSZgdh88jn9CjKcc8kF";
char ChannelsCChexstr[67] = { "023550b3aa8cad70f475697bc077dcd2d54ba761f4852366373c1089c949256819" };
uint8_t ChannelsCCpriv[32] = {  };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Oracles
#define FUNCNAME IsOraclesInput
#define EVALCODE EVAL_ORACLES
const char *OraclesCCaddr = "";
const char *OraclesNormaladdr = "RZjLEvdRLXEMsUeX15VKVFzxTfSSedgRvb";
char OraclesCChexstr[67] = { "02774088fcf38b01fee81403a2b37adf2b6d8a95577dfc83b88ddb2766fe2f0802" };
uint8_t OraclesCCpriv[32] = {  };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Prices
#define FUNCNAME IsPricesInput
#define EVALCODE EVAL_PRICES
const char *PricesCCaddr = "";
const char *PricesNormaladdr = "RuwtCjYDY2H6WyeVzjcW21Kfv3tHyAmQEh";
char PricesCChexstr[67] = { "036148bf96170c7b96282ec57bdc6ae461def42b0dd674dd7ce51eea6736743a66" };
uint8_t PricesCCpriv[32] = {  };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Pegs
#define FUNCNAME IsPegsInput
#define EVALCODE EVAL_PEGS
const char *PegsCCaddr = "";
const char *PegsNormaladdr = "Rj8sEwfcJVY9F4cnsTK5GNn7yWpsCbRMFU";
char PegsCChexstr[67] = { "02c35479e76249bb67ca23f78e1fe3fe2a95d4951f103b55237c44063cb898f6aa" };
uint8_t PegsCCpriv[32] = {  };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Triggers
#define FUNCNAME IsTriggersInput
#define EVALCODE EVAL_TRIGGERS
const char *TriggersCCaddr = "";
const char *TriggersNormaladdr = "RqSHi1rzae53L5N5uSUYd6LMXHiHpJxrJa";
char TriggersCChexstr[67] = { "03748bf6436b898475fbb390375e1697c2612f3461257ddd1eff37d1eb10ca763d" };
uint8_t TriggersCCpriv[32] = {  };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Payments
#define FUNCNAME IsPaymentsInput
#define EVALCODE EVAL_PAYMENTS
const char *PaymentsCCaddr = "";
const char *PaymentsNormaladdr = "RfJTfTQ9cY3BKkXXaEeT5KRuBjXTGJMYik";
char PaymentsCChexstr[67] = { "02fa35c24ca68526454abd5864efb08bd0b115852ce89efe6aa809a270c4e99651" };
uint8_t PaymentsCCpriv[32] = {  };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Gateways
#define FUNCNAME IsGatewaysInput
#define EVALCODE EVAL_GATEWAYS
const char *GatewaysCCaddr = "";
const char *GatewaysNormaladdr = "Rdkt5svpEJgyiHC16cp3GWoUavUFeS6MXq"; // wif 
char GatewaysCChexstr[67] = { "0270e083ba6469b618df454d3d402175cc722ff051d6095882afb022d5c222ba17" };
uint8_t GatewaysCCpriv[32] = { };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

struct CCcontract_info *CCinit(struct CCcontract_info *cp, uint8_t evalcode)
{
    cp->evalcode = evalcode;
    switch ( evalcode )
    {
        case EVAL_ASSETS:
            strcpy(cp->unspendableCCaddr,AssetsCCaddr);
            strcpy(cp->normaladdr,AssetsNormaladdr);
            strcpy(cp->CChexstr,AssetsCChexstr);
            memcpy(cp->CCpriv,AssetsCCpriv,32);
            cp->validate = AssetsValidate;
            cp->ismyvin = IsAssetsInput;
            break;
        case EVAL_FAUCET:
            strcpy(cp->unspendableCCaddr,FaucetCCaddr);
            strcpy(cp->normaladdr,FaucetNormaladdr);
            strcpy(cp->CChexstr,FaucetCChexstr);
            memcpy(cp->CCpriv,FaucetCCpriv,32);
            cp->validate = FaucetValidate;
            cp->ismyvin = IsFaucetInput;
            break;
        case EVAL_REWARDS:
            strcpy(cp->unspendableCCaddr,RewardsCCaddr);
            strcpy(cp->normaladdr,RewardsNormaladdr);
            strcpy(cp->CChexstr,RewardsCChexstr);
            memcpy(cp->CCpriv,RewardsCCpriv,32);
            cp->validate = RewardsValidate;
            cp->ismyvin = IsRewardsInput;
            break;
        case EVAL_DICE:
            strcpy(cp->unspendableCCaddr,DiceCCaddr);
            strcpy(cp->normaladdr,DiceNormaladdr);
            strcpy(cp->CChexstr,DiceCChexstr);
            memcpy(cp->CCpriv,DiceCCpriv,32);
            cp->validate = DiceValidate;
            cp->ismyvin = IsDiceInput;
            break;
        case EVAL_LOTTO:
            strcpy(cp->unspendableCCaddr,LottoCCaddr);
            strcpy(cp->normaladdr,LottoNormaladdr);
            strcpy(cp->CChexstr,LottoCChexstr);
            memcpy(cp->CCpriv,LottoCCpriv,32);
            cp->validate = LottoValidate;
            cp->ismyvin = IsLottoInput;
            break;
        case EVAL_FSM:
            strcpy(cp->unspendableCCaddr,FSMCCaddr);
            strcpy(cp->normaladdr,FSMNormaladdr);
            strcpy(cp->CChexstr,FSMCChexstr);
            memcpy(cp->CCpriv,FSMCCpriv,32);
            cp->validate = FSMValidate;
            cp->ismyvin = IsFSMInput;
            break;
        case EVAL_AUCTION:
            strcpy(cp->unspendableCCaddr,AuctionCCaddr);
            strcpy(cp->normaladdr,AuctionNormaladdr);
            strcpy(cp->CChexstr,AuctionCChexstr);
            memcpy(cp->CCpriv,AuctionCCpriv,32);
            cp->validate = AuctionValidate;
            cp->ismyvin = IsAuctionInput;
            break;
        case EVAL_HEIR:
            strcpy(cp->unspendableCCaddr,HeirCCaddr);
            strcpy(cp->normaladdr,HeirNormaladdr);
            strcpy(cp->CChexstr,HeirCChexstr);
            memcpy(cp->CCpriv,HeirCCpriv,32);
            cp->validate = HeirValidate;
            cp->ismyvin = IsHeirInput;
            break;
        case EVAL_CHANNELS:
            strcpy(cp->unspendableCCaddr,ChannelsCCaddr);
            strcpy(cp->normaladdr,ChannelsNormaladdr);
            strcpy(cp->CChexstr,ChannelsCChexstr);
            memcpy(cp->CCpriv,ChannelsCCpriv,32);
            cp->validate = ChannelsValidate;
            cp->ismyvin = IsChannelsInput;
            break;
        case EVAL_ORACLES:
            strcpy(cp->unspendableCCaddr,OraclesCCaddr);
            strcpy(cp->normaladdr,OraclesNormaladdr);
            strcpy(cp->CChexstr,OraclesCChexstr);
            memcpy(cp->CCpriv,OraclesCCpriv,32);
            cp->validate = OraclesValidate;
            cp->ismyvin = IsOraclesInput;
            break;
        case EVAL_PRICES:
            strcpy(cp->unspendableCCaddr,PricesCCaddr);
            strcpy(cp->normaladdr,PricesNormaladdr);
            strcpy(cp->CChexstr,PricesCChexstr);
            memcpy(cp->CCpriv,PricesCCpriv,32);
            cp->validate = PricesValidate;
            cp->ismyvin = IsPricesInput;
            break;
        case EVAL_PEGS:
            strcpy(cp->unspendableCCaddr,PegsCCaddr);
            strcpy(cp->normaladdr,PegsNormaladdr);
            strcpy(cp->CChexstr,PegsCChexstr);
            memcpy(cp->CCpriv,PegsCCpriv,32);
            cp->validate = PegsValidate;
            cp->ismyvin = IsPegsInput;
            break;
        case EVAL_TRIGGERS:
            strcpy(cp->unspendableCCaddr,TriggersCCaddr);
            strcpy(cp->normaladdr,TriggersNormaladdr);
            strcpy(cp->CChexstr,TriggersCChexstr);
            memcpy(cp->CCpriv,TriggersCCpriv,32);
            cp->validate = TriggersValidate;
            cp->ismyvin = IsTriggersInput;
            break;
        case EVAL_PAYMENTS:
            strcpy(cp->unspendableCCaddr,PaymentsCCaddr);
            strcpy(cp->normaladdr,PaymentsNormaladdr);
            strcpy(cp->CChexstr,PaymentsCChexstr);
            memcpy(cp->CCpriv,PaymentsCCpriv,32);
            cp->validate = PaymentsValidate;
            cp->ismyvin = IsPaymentsInput;
            break;
        case EVAL_GATEWAYS:
            strcpy(cp->unspendableCCaddr,GatewaysCCaddr);
            strcpy(cp->normaladdr,GatewaysNormaladdr);
            strcpy(cp->CChexstr,GatewaysCChexstr);
            memcpy(cp->CCpriv,GatewaysCCpriv,32);
            cp->validate = GatewaysValidate;
            cp->ismyvin = IsGatewaysInput;
            break;
    }
    return cp;
}

