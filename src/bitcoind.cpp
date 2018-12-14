// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "clientversion.h"
#include "rpcserver.h"
#include "init.h"
#include "main.h"
#include "noui.h"
#include "scheduler.h"
#include "util.h"
#include "httpserver.h"
#include "httprpc.h"
#include "rpcserver.h"

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
#define SAFECOIN_ASSETCHAIN_MAXLEN 65
extern char ASSETCHAINS_SYMBOL[SAFECOIN_ASSETCHAIN_MAXLEN];
void safecoin_passport_iteration();
int32_t safecoin_longestchain();

void WaitForShutdown(boost::thread_group* threadGroup)
{
    bool fShutdown = ShutdownRequested();
    // Tell the main threads to shutdown.
    while (!fShutdown)
    {
        //fprintf(stderr,"call passport iteration\n");
        if ( ASSETCHAINS_SYMBOL[0] == 0 )
        {
            safecoin_passport_iteration();
            MilliSleep(10000);
        }
        else
        {
            safecoin_longestchain();
            MilliSleep(20000);
        }
        fShutdown = ShutdownRequested();
    }
    if (threadGroup)
    {
        Interrupt(*threadGroup);
        threadGroup->join_all();
    }
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//
extern int32_t IS_SAFECOIN_NOTARY,USE_EXTERNAL_PUBKEY,ASSETCHAIN_INIT;
extern std::string NOTARY_PUBKEY;
int32_t safecoin_is_issuer();
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
        return false;
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
        } catch (const missing_zcash_conf& e) {
            try
            {

#ifdef _WIN32
                fprintf(stdout,
                    "------------------------------------------------------------------\n"
                    "                        ERROR:\n"
                    " The configuration file safecoin.conf is missing.\n"
                    " Please create a valid safecoin.conf in the application data directory.\n"
                    " The default application data directories are:\n"
                    "\n"
                    " Windows (pre Vista): C:\\Documents and Settings\\Username\\Application Data\\Safecoin\n"
                    " Windows (Vista and later): C:\\Users\\Username\\AppData\\Roaming\\Safecoin\n"
                    "\n"
                    " You can find the default configuration file at:\n"
                    " https://github.com/Fair-Exchange/safecoin/blob/master/contrib/debian/examples/safecoin.conf\n"
                    "\n"
                    "                        WARNING:\n"
                    " Running the default configuration file without review is considered a potential risk, as safecoind\n"
                    " might accidentally compromise your privacy if there is a default option that you need to change!\n"
                    "\n"
                    " Please create a valid safecoin.conf and restart to safecoind continue.\n"
                    "------------------------------------------------------------------\n");
                return false;
#endif
                // Warn user about using default config file
                fprintf(stdout,
                    "------------------------------------------------------------------\n"
                    "                        WARNING:\n"
                    "Automatically copying the default config file to:\n"
                    "\n"
#ifdef  __APPLE__
                    "~/Library/Application Support/Safecoin\n"
#else
                    "~/.safecoin/safecoin.conf\n"
#endif
                    "\n"
                    " Running the default configuration file without review is considered a potential risk, as safecoind\n"
                    " might accidentally compromise your privacy if there is a default option that you need to change!\n"
                    "\n"
                    "           Please restart safecoind to continue.\n"
                    "           You will not see this warning again.\n"
                    "------------------------------------------------------------------\n");


#ifdef __APPLE__
                // On Mac OS try to copy the default config file if safecoind is started from source folder safecoin/src/safecoind
                std::string strConfPath("../contrib/debian/examples/safecoin.conf");
                if (!boost::filesystem::exists(strConfPath)){
                    strConfPath = "contrib/debian/examples/safecoin.conf";
                }
#else
                std::string strConfPath("/usr/share/doc/safecoin/examples/safecoin.conf");

                if (!boost::filesystem::exists(strConfPath))
                {
                    strConfPath = "contrib/debian/examples/safecoin.conf";
                }

                if (!boost::filesystem::exists(strConfPath))
                {
                    strConfPath = "../contrib/debian/examples/safecoin.conf";
                }
#endif
                // Copy default config file
                std::ifstream src(strConfPath, std::ios::binary);
                src.exceptions(std::ifstream::failbit | std::ifstream::badbit);

                std::ofstream dst(GetConfigFile().string().c_str(), std::ios::binary);
                dst << src.rdbuf();
                return false;
            } catch (const std::exception& e) {                
                fprintf(stdout,
                    "------------------------------------------------------------------\n"
                    " There was an error copying the default configuration file!!!!\n"
                    "\n"
                    " Please create a configuration file in the data directory.\n"
                    " The default application data directories are:\n"
                    " Windows (pre Vista): C:\\Documents and Settings\\Username\\Application Data\\Safecoin\n"
                    " Windows (Vista and later): C:\\Users\\Username\\AppData\\Roaming\\Safecoin\n"
                    "\n"
                    " You can find the default configuration file at:\n"
                    " https://github.com/Fair-Exchange/safecoin/blob/master/contrib/debian/examples/safecoin.conf\n"
                    "\n"
                    "                        WARNING:\n"
                    " Running the default configuration file without review is considered a potential risk, as safecoind\n"
                    " might accidentally compromise your privacy if there is a default option that you need to change!\n"
                    "------------------------------------------------------------------\n");
                fprintf(stderr, "Error copying configuration file: %s\n", e.what());
                return false;
            }
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
        bool fCommandLine = false;
        for (int i = 1; i < argc; i++)
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "safecoin:"))
                fCommandLine = true;

        if (fCommandLine)
        {
            fprintf(stderr, "Error: There is no RPC client functionality in safecoind. Use the safecoin-cli utility instead.\n");
            exit(1);
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
            {
                return true;
            }
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

    return (AppInit(argc, argv) ? 0 : 1);
}
