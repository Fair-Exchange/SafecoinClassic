/******************************************************************************
 * Copyright © 2014-2017 The SuperNET Developers.                             *
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

#define SATOSHIDEN ((uint64_t)100000000L)
#define dstr(x) ((double)(x) / SATOSHIDEN)

#define SAFECOIN_ENDOFERA 77195

int64_t MAX_MONEY = 36200000 * 100000000LL;
extern uint8_t NOTARY_PUBKEY33[];

#ifdef notanymore

uint64_t safecoin_moneysupply(int32_t height)
{
    if ( height <= 1 || ASSETCHAINS_SYMBOL[0] == 0 )
        return(0);
    else return(COIN * 100000000 + (height-1) * 3 );
}
#endif
