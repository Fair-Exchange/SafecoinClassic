// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "clientversion.h"
#include "rpc/server.h"
#include "init.h"
#include "main.h"
#include "noui.h"
#include "scheduler.h"
#include "util.h"
#include "httpserver.h"
#include "httprpc.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include <stdio.h>

#ifdef _WIN32
#define frpintf(...)
#define printf(...)
#endif

/* Introduction text for doxygen: */

/*! \mainpage Developer documentation
 *
 * \section intro_sec Introduction
 *
 * This is the developer documentation of the reference client for an experimental new digital currency called Bitcoin (https://www.bitcoin.org/),
 * which enables instant payments to anyone, anywhere in the world. Bitcoin uses peer-to-peer technology to operate
 * with no central authority: managing transactions and issuing money are carried out collectively by the network.
 *
 * The software is a community-driven open source project, released under the MIT license.
 *
 * \section Navigation
 * Use the buttons <code>Namespaces</code>, <code>Classes</code> or <code>Files</code> at the top of the page to start navigating the code.
 */

static bool fDaemon;
#include "safecoin_defs.h"
#define SAFECOIN_ASSETCHAIN_MAXLEN 65
extern char ASSETCHAINS_SYMBOL[SAFECOIN_ASSETCHAIN_MAXLEN];
void safecoin_passport_iteration();
uint64_t safecoin_interestsum();
int32_t safecoin_longestchain();

void WaitForShutdown(boost::thread_group* threadGroup)
{
    // Tell the main threads to shutdown.
    while (!ShutdownRequested())
    {
        //fprintf(stderr,"call passport iteration\n");
        if ( ASSETCHAINS_SYMBOL[0] == '\0' )
        {
            safecoin_passport_iteration();
            MilliSleep(10000);
        }
        else
        {
            //safecoin_interestsum();
            //safecoin_longestchain();
            MilliSleep(20000);
        }
    }
    if (threadGroup != nullptr)
    {
        Interrupt(*threadGroup);
        threadGroup->join_all();
    }
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//
extern bool IS_SAFECOIN_NOTARY;
extern int32_t USE_EXTERNAL_PUBKEY,ASSETCHAIN_INIT;
extern std::string NOTARY_PUBKEY;
bool safecoin_is_issuer();
void safecoin_passport_iteration();

bool AppInit(int argc, char* argv[])
{
    boost::thread_group threadGroup;
    CScheduler scheduler;

    bool fRet = false;

    //
    // Parameters
    //
    // If Qt is used, parameters/safecoin.conf are parsed in qt/bitcoin.cpp's main()
    ParseParameters(argc, argv);

    // Process help and version before taking care about datadir
    if (mapArgs.count("-?") || mapArgs.count("-h") ||  mapArgs.count("-help") || mapArgs.count("-version"))
    {
        std::string strUsage = _("Safecoin Daemon") + " " + _("version") + " " + FormatFullVersion() + "\n" + PrivacyInfo();

        if (mapArgs.count("-version"))
        {
            strUsage += LicenseInfo();
        }
        else
        {
            strUsage += "\n" + _("Usage:") + "\n" +
                  "  safecoind [options]                     " + _("Start Safecoin Daemon") + "\n";

            strUsage += "\n" + HelpMessage(HMM_BITCOIND);
        }

        fprintf(stdout, "%s", strUsage.c_str());
        return true;
    }

    try
    {
        void safecoin_args(char *argv0);
        safecoin_args(argv[0]);
        fprintf(stderr,"call safecoin_args.(%s) NOTARY_PUBKEY.(%s)\n",argv[0],NOTARY_PUBKEY.c_str());
        while ( ASSETCHAIN_INIT == 0 )
        {
            //if ( safecoin_is_issuer() != 0 )
            //    safecoin_passport_iteration();
            #ifdef _WIN32
            boost::this_thread::sleep_for(boost::chrono::seconds(1));
            #else
            sleep(1);
            #endif
        }
        printf("initialized %s at %u\n",ASSETCHAINS_SYMBOL,(uint32_t)time(NULL));
        if (!boost::filesystem::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
            return false;
        }
        try
        {
            ReadConfigFile(mapArgs, mapMultiArgs);
        } catch (const missing_safecoin_conf& e) {
            fprintf(stderr,
                (_("Before starting safecoind, you need to create a configuration file:\n"
                   "%s\n"
                   "It can be completely empty! That indicates you are happy with the default\n"
                   "configuration of safecoind. But requiring a configuration file to start ensures\n"
                   "that safecoind won't accidentally compromise your privacy if there was a default\n"
                   "option you needed to change.\n"
                   "\n"
                   "You can look at the example configuration file for suggestions of default\n"
                   "options that you may want to change. It should be in one of these locations,\n"
                   "depending on how you installed Safecoin:\n") +
                 _("- Source code:  %s\n"
                   "- .deb package: %s\n")).c_str(),
                GetConfigFile().string().c_str(),
                "contrib/debian/examples/safecoin.conf",
                "/usr/share/doc/safecoin/examples/safecoin.conf");
            return false;
        } catch (const std::exception& e) {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            return false;
        }
        // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
        if (!SelectParamsFromCommandLine()) {
            fprintf(stderr, "Error: Invalid combination of -regtest and -testnet.\n");
            return false;
        }

        // Command-line RPC
        for (int i = 1; i < argc; i++) {
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "safecoin:")) {
                fprintf(stderr, "Error: There is no RPC client functionality in safecoind. Use the safecoin-cli utility instead.\n");
                exit(EXIT_FAILURE);
            }
        }

#ifndef _WIN32
        fDaemon = GetBoolArg("-daemon", false);
        if (fDaemon)
        {
            fprintf(stdout, "Safecoin %s server starting\n",ASSETCHAINS_SYMBOL);

            // Daemonize
            pid_t pid = fork();
            if (pid < 0)
            {
                fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
                return false;
            }
            if (pid > 0) // Parent process, pid is child process id
                return true;
            // Child process falls through to rest of initialization

            pid_t sid = setsid();
            if (sid < 0)
                fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
        }
#endif
        SoftSetBoolArg("-server", true);

        fRet = AppInit2(threadGroup, scheduler);
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }
    if (!fRet)
    {
        Interrupt(threadGroup);
        // threadGroup.join_all(); was left out intentionally here, because we didn't re-test all of
        // the startup-failure cases to make sure they don't result in a hang due to some
        // thread-blocking-waiting-for-another-thread-during-startup case
    } else {
        WaitForShutdown(&threadGroup);
    }
    Shutdown();

    return fRet;
}

int main(int argc, char* argv[])
{
    SetupEnvironment();

    // Connect bitcoind signal handlers
    noui_connect();

    return AppInit(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE;
}
