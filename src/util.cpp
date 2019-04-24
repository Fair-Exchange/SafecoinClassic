// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "util.h"

#include "chainparamsbase.h"
#include "random.h"
#include "serialize.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "safecoin_defs.h"

#include <stdarg.h>
#include <sstream>
#include <vector>
#include <stdio.h>

#if (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
#include <pthread.h>
#include <pthread_np.h>
#endif

#ifndef _WIN32
// for posix_fallocate
#ifdef __linux__

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#define _POSIX_C_SOURCE 200112L

#endif // __linux__

#include <algorithm>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#else

#ifdef _MSC_VER
#pragma warning(disable:4786)
#pragma warning(disable:4804)
#pragma warning(disable:4805)
#pragma warning(disable:4717)
#endif

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501

#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501

#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <io.h> /* for _commit */
#include <shlobj.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/foreach.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>
#include <openssl/conf.h>

// Work around clang compilation problem in Boost 1.46:
// /usr/include/boost/program_options/detail/config_file.hpp:163:17: error: call to function 'to_internal' that is neither visible in the template definition nor found by argument-dependent lookup
// See also: http://stackoverflow.com/questions/10020179/compilation-fail-in-boost-librairies-program-options
//           http://clang.debian.net/status.php?version=3.0&key=CANNOT_FIND_FUNCTION
namespace boost {

    namespace program_options {
        std::string to_internal(const std::string&);
    }

} // namespace boost

using namespace std;

map<string, string> mapArgs;
map<string, vector<string> > mapMultiArgs;
bool fDebug = false;
bool fPrintToConsole = false;
bool fPrintToDebugLog = true;
bool fDaemon = false;
bool fServer = false;
string strMiscWarning;
bool fLogTimestamps = DEFAULT_LOGTIMESTAMPS;
bool fLogTimeMicros = DEFAULT_LOGTIMEMICROS;
bool fLogIPs = DEFAULT_LOGIPS;
atomic<bool> fReopenDebugLog(false);
CTranslationInterface translationInterface;

/** Init OpenSSL library multithreading support */
static CCriticalSection** ppmutexOpenSSL;
void locking_callback(int mode, int i, const char* file, int line) NO_THREAD_SAFETY_ANALYSIS
{
    if (mode & CRYPTO_LOCK) {
        ENTER_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    } else {
        LEAVE_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    }
}

// Init
static class CInit
{
public:
    CInit()
    {
        // Init OpenSSL library multithreading support
        ppmutexOpenSSL = (CCriticalSection**)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(CCriticalSection*));
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            ppmutexOpenSSL[i] = new CCriticalSection();
        CRYPTO_set_locking_callback(locking_callback);

        // OpenSSL can optionally load a config file which lists optional loadable modules and engines.
        // We don't use them so we don't require the config. However some of our libs may call functions
        // which attempt to load the config file, possibly resulting in an exit() or crash if it is missing
        // or corrupt. Explicitly tell OpenSSL not to try to load the file. The result for our libs will be
        // that the config appears to have been loaded and there are no modules/engines available.
        OPENSSL_no_config();
    }
    ~CInit()
    {
        // Shutdown OpenSSL library multithreading support
        CRYPTO_set_locking_callback(NULL);
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            delete ppmutexOpenSSL[i];
        OPENSSL_free(ppmutexOpenSSL);
    }
}
instance_of_cinit;

/**
 * LogPrintf() has been broken a couple of times now
 * by well-meaning people adding mutexes in the most straightforward way.
 * It breaks because it may be called by global destructors during shutdown.
 * Since the order of destruction of static/global objects is undefined,
 * defining a mutex as a global object doesn't work (the mutex gets
 * destroyed, and then some later destructor calls OutputDebugStringF,
 * maybe indirectly, and you get a core dump at shutdown trying to lock
 * the mutex).
 */

static boost::once_flag debugPrintInitFlag = BOOST_ONCE_INIT;

/**
 * We use boost::call_once() to make sure mutexDebugLog and
 * vMsgsBeforeOpenLog are initialized in a thread-safe manner.
 *
 * NOTE: fileout, mutexDebugLog and sometimes vMsgsBeforeOpenLog
 * are leaked on exit. This is ugly, but will be cleaned up by
 * the OS/libc. When the shutdown sequence is fully audited and
 * tested, explicit destruction of these objects can be implemented.
 */
static FILE* fileout = nullptr;
static boost::mutex* mutexDebugLog = nullptr;
static list<string> *vMsgsBeforeOpenLog;

[[noreturn]] void new_handler_terminate()
{
    // Rather than throwing bad-alloc if allocation fails, terminate
    // immediately to (try to) avoid chain corruption.
    // Since LogPrintf may itself allocate memory, set the handler directly
    // to terminate first.
    set_new_handler(terminate);
    fputs("Error: Out of memory. Terminating.\n", stderr);
    LogPrintf("Error: Out of memory. Terminating.\n");

    // The log was successful, terminate now.
    terminate();
};

static int FileWriteStr(const string &str, FILE *fp)
{
    return fwrite(str.data(), 1, str.size(), fp);
}

static void DebugPrintInit()
{
    assert(mutexDebugLog == nullptr);
    mutexDebugLog = new boost::mutex();
    vMsgsBeforeOpenLog = new list<string>;
}

void OpenDebugLog()
{
    boost::call_once(&DebugPrintInit, debugPrintInitFlag);
    boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

    assert(fileout == nullptr);
    assert(vMsgsBeforeOpenLog);
    boost::filesystem::path pathDebug = GetDataDir() / "debug.log";
    fileout = fopen(pathDebug.string().c_str(), "a");
    if (fileout)
        setbuf(fileout, nullptr); // unbuffered

    // dump buffered messages from before we opened the log
    while (!vMsgsBeforeOpenLog->empty()) {
        FileWriteStr(vMsgsBeforeOpenLog->front(), fileout);
        vMsgsBeforeOpenLog->pop_front();
    }

    delete vMsgsBeforeOpenLog;
    vMsgsBeforeOpenLog = nullptr;
}

bool LogAcceptCategory(const char* category)
{
    if (category != nullptr)
    {
        if (!fDebug)
            return false;

        // Give each thread quick access to -debug settings.
        // This helps prevent issues debugging global destructors,
        // where mapMultiArgs might be deleted before another
        // global destructor calls LogPrint()
        static boost::thread_specific_ptr<set<string>> ptrCategory;
        if (ptrCategory.get() == nullptr)
        {
            const vector<string>& categories = mapMultiArgs["-debug"];
            ptrCategory.reset(new set<string>(categories.begin(), categories.end()));
            // thread_specific_ptr automatically deletes the set when the thread ends.
        }
        const set<string>& setCategories = *ptrCategory.get();

        // if not debugging everything and not debugging specific category, LogPrint does nothing.
        if (setCategories.count("") == 0 &&
            setCategories.count("1") == 0 &&
            setCategories.count(category) == 0)
            return false;
    }
    return true;
}

/**
 * fStartedNewLine is a state variable held by the calling context that will
 * suppress printing of the timestamp when multiple calls are made that don't
 * end in a newline. Initialize it to true, and hold it, in the calling context.
 */
static string LogTimestampStr(const string &str, bool *fStartedNewLine)
{
    string strStamped;

    if (!fLogTimestamps)
        return str;

    strStamped = *fStartedNewLine ? DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()) + ' ' + str : str;
    *fStartedNewLine = !str.empty() && str[str.size()-1] == '\n';

    return strStamped;
}

int LogPrintStr(const string &str)
{
    int ret = 0; // Returns total number of characters written
    static bool fStartedNewLine = true;
    if (fPrintToConsole)
    {
        // print to console
        ret = fwrite(str.data(), 1, str.size(), stdout);
        fflush(stdout);
    }
    else if (fPrintToDebugLog)
    {
        boost::call_once(&DebugPrintInit, debugPrintInitFlag);
        boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

        string strTimestamped = LogTimestampStr(str, &fStartedNewLine);

        // buffer if we haven't opened the log yet
        if (fileout == nullptr) {
            assert(vMsgsBeforeOpenLog);
            ret = strTimestamped.length();
            vMsgsBeforeOpenLog->push_back(strTimestamped);
        }
        else
        {
            // reopen the log file, if requested
            if (fReopenDebugLog) {
                fReopenDebugLog = false;
                boost::filesystem::path pathDebug = GetDataDir() / "debug.log";
                if (freopen(pathDebug.string().c_str(),"a",fileout) != nullptr)
                    setbuf(fileout, nullptr); // unbuffered
            }

            ret = FileWriteStr(strTimestamped, fileout);
        }
    }
    return ret;
}

static void InterpretNegativeSetting(string name, map<string, string>& mapSettingsRet)
{
    // interpret -nofoo as -foo=0 (and -nofoo=0 as -foo=1) as long as -foo not set
    if (name.find("-no") == 0)
    {
        string positive("-");
        positive.append(name.begin()+3, name.end());
        if (mapSettingsRet.count(positive) == 0)
        {
            bool value = !GetBoolArg(name, false);
            mapSettingsRet[positive] = value ? "1" : "0";
        }
        mapSettingsRet.erase(mapSettingsRet.find(name));
    }
}

void ParseParameters(int argc, const char* const argv[])
{
    mapArgs.clear();
    mapMultiArgs.clear();

    for (int i = 1; i < argc; i++)
    {
        string str(argv[i]);
        string strValue;
        size_t is_index = str.find('=');
        if (is_index != string::npos)
        {
            strValue = str.substr(is_index+1);
            str = str.substr(0, is_index);
        }
#ifdef _WIN32
        boost::to_lower(str);
        if (boost::algorithm::starts_with(str, "/"))
            str = "-" + str.substr(1);
#endif

        if (str[0] != '-')
            break;

        // Interpret --foo as -foo.
        // If both --foo and -foo are set, the last takes effect.
        if (str.length() > 1 && str[1] == '-')
            str = str.substr(1);

        mapArgs[str] = strValue;
        mapMultiArgs[str].push_back(strValue);
    }

    // New 0.6 features:
    BOOST_FOREACH(const PAIRTYPE(string,string)& entry, mapArgs)
    {
        // interpret -nofoo as -foo=0 (and -nofoo=0 as -foo=1) as long as -foo not set
        InterpretNegativeSetting(entry.first, mapArgs);
    }
}

void Split(const string& strVal, uint64_t *outVals, const uint64_t nDefault)
{
    stringstream ss(strVal);
    vector<uint64_t> vec;

    uint64_t i, nLast, numVals = 0;

    while ( ss.peek() == ' ' )
        ss.ignore();

    while ( ss >> i )
    {
        outVals[numVals++] = i;

        while ( ss.peek() == ' ' )
            ss.ignore();
        if ( ss.peek() == ',' )
            ss.ignore();
        while ( ss.peek() == ' ' )
            ss.ignore();
    }

    nLast = numVals > 0 ? outVals[numVals - 1] : nDefault;

    for ( i = numVals; i < ASSETCHAINS_MAX_ERAS; i++ )
        outVals[i] = nLast;
}

string GetArg(const string& strArg, const string& strDefault)
{
    return mapArgs.count(strArg) ? mapArgs[strArg] : strDefault;
}

int64_t GetArg(const string& strArg, int64_t nDefault)
{
    return mapArgs.count(strArg) ? atoi64(mapArgs[strArg]) : nDefault;
}

bool GetBoolArg(const string& strArg, bool fDefault)
{
    return mapArgs.count(strArg) ? mapArgs[strArg].empty() || atoi(mapArgs[strArg]) != 0 : fDefault;
}

bool SoftSetArg(const string& strArg, const string& strValue)
{
    if (mapArgs.count(strArg))
        return false;
    mapArgs[strArg] = strValue;
    return true;
}

bool SoftSetBoolArg(const string& strArg, bool fValue)
{
    return SoftSetArg(strArg, fValue ? "1" : "0");
}

static const int screenWidth = 79;
static const int optIndent = 2;
static const int msgIndent = 7;

string HelpMessageGroup(const string &message) {
    return string(message) + string("\n\n");
}

string HelpMessageOpt(const string &option, const string &message) {
    return string(optIndent, ' ') + string(option) + string("\n") +
           string(msgIndent, ' ') + FormatParagraph(message, screenWidth - msgIndent, msgIndent) +
           string("\n\n");
}

static string FormatException(const exception* pex, const char* pszThread)
{
#ifdef _WIN32
    char pszModule[MAX_PATH] = "";
    GetModuleFileNameA(nullptr, pszModule, sizeof(pszModule));
#else
    const char* pszModule = "Safecoin";
#endif
    if (pex)
        return strprintf(
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, pszThread);
    else
        return strprintf(
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
}

void PrintExceptionContinue(const exception* pex, const char* pszThread)
{
    string message = FormatException(pex, pszThread);
    LogPrintf("\n\n************************\n%s\n", message);
    fprintf(stderr, "\n\n************************\n%s\n", message.c_str());
    strMiscWarning = message;
}

extern char ASSETCHAINS_SYMBOL[SAFECOIN_ASSETCHAIN_MAXLEN];
//int64_t MAX_MONEY = 200000000 * 100000000LL;

boost::filesystem::path GetDefaultDataDir()
{
    namespace fs = boost::filesystem;
    char symbol[SAFECOIN_ASSETCHAIN_MAXLEN];
    if ( ASSETCHAINS_SYMBOL[0] != '\0' )
        strcpy(symbol,ASSETCHAINS_SYMBOL);
    else symbol[0] = '\0';
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\Safecoin
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\Safecoin
    // Mac: ~/Library/Application Support/Safecoin
    // Unix: ~/.safecoin
#ifdef _WIN32
    // Windows
    if ( symbol[0] == '\0' )
        return GetSpecialFolderPath(CSIDL_APPDATA) / "Safecoin";
    else
        return GetSpecialFolderPath(CSIDL_APPDATA) / "Safecoin" / symbol;
#else
    fs::path pathRet;
    char* pszHome = getenv("HOME");
    if (pszHome == nullptr || strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
#ifdef MAC_OSX
    // Mac
    pathRet /= "Library/Application Support";
    TryCreateDirectory(pathRet);
    if ( symbol[0] == '\0' )
        return pathRet / "Safecoin";
    else
    {
        pathRet /= "Safecoin";
        TryCreateDirectory(pathRet);
        return pathRet / symbol;
    }
#else
    // Unix
    if ( symbol[0] == '\0' )
        return pathRet / ".safecoin";
    else
        return pathRet / ".safecoin" / symbol;
#endif
#endif
}

static boost::filesystem::path pathCached;
static boost::filesystem::path pathCachedNetSpecific;
static boost::filesystem::path zc_paramsPathCached;
static CCriticalSection csPathCached;

static boost::filesystem::path ZC_GetBaseParamsDir()
{
    // Copied from GetDefaultDataDir and adapter for zcash params.

    namespace fs = boost::filesystem;
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\ZcashParams
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\ZcashParams
    // Mac: ~/Library/Application Support/ZcashParams
    // Unix: ~/.zcash-params
    fs::path pathRet;
#ifdef _WIN32
    return GetSpecialFolderPath(CSIDL_APPDATA) / "ZcashParams";
#else
    char* pszHome = getenv("HOME");
    if (pszHome == nullptr || strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
#ifdef MAC_OSX
    // Mac
    pathRet /= "Library/Application Support";
    TryCreateDirectory(pathRet);
    return pathRet / "ZcashParams";
#else
    // Unix
    return pathRet / ".zcash-params";
#endif
#endif
}

const boost::filesystem::path &ZC_GetParamsDir()
{
    namespace fs = boost::filesystem;

    LOCK(csPathCached); // Reuse the same lock as upstream.

    fs::path &path = zc_paramsPathCached;

    // This can be called during exceptions by LogPrintf(), so we cache the
    // value so we don't have to do memory allocations after that.
    if (!path.empty())
        return path;

    path = ZC_GetBaseParamsDir();

    return path;
}

// Return the user specified export directory.  Create directory if it doesn't exist.
// If user did not set option, return an empty path.
// If there is a filesystem problem, throw an exception.
const boost::filesystem::path GetExportDir()
{
    namespace fs = boost::filesystem;
    fs::path path;
    if (mapArgs.count("-exportdir")) {
        path = fs::system_complete(mapArgs["-exportdir"]);
        if (fs::exists(path) && !fs::is_directory(path))
            throw runtime_error(strprintf("The -exportdir '%s' already exists and is not a directory", path.string()));
        if (!fs::exists(path) && !fs::create_directories(path))
            throw runtime_error(strprintf("Failed to create directory at -exportdir '%s'", path.string()));
    }
    return path;
}


const boost::filesystem::path &GetDataDir(bool fNetSpecific)
{
    namespace fs = boost::filesystem;

    LOCK(csPathCached);

    fs::path &path = fNetSpecific ? pathCachedNetSpecific : pathCached;

    // This can be called during exceptions by LogPrintf(), so we cache the
    // value so we don't have to do memory allocations after that.
    if (!path.empty())
        return path;

    if (mapArgs.count("-datadir")) {
        path = fs::system_complete(mapArgs["-datadir"]);
        if (!fs::is_directory(path)) {
            path = "";
            return path;
        }
    } else {
        path = GetDefaultDataDir();
    }
    if (fNetSpecific)
        path /= BaseParams().DataDir();

    fs::create_directories(path);
    //string assetpath = path + "/assets";
    //boost::filesystem::create_directory(assetpath);
    return path;
}

void ClearDatadirCache()
{
    pathCached = boost::filesystem::path();
    pathCachedNetSpecific = boost::filesystem::path();
}

boost::filesystem::path GetConfigFile()
{
    char confname[512];
    if ( ASSETCHAINS_SYMBOL[0] != '\0' )
        sprintf(confname,"%s.conf",ASSETCHAINS_SYMBOL);
    else
#ifdef __APPLE__
        strcpy(confname,"Safecoin.conf");
#else
        strcpy(confname,"safecoin.conf");
#endif
    boost::filesystem::path pathConfigFile(GetArg("-conf",confname));
    if (!pathConfigFile.is_complete())
        pathConfigFile = GetDataDir(false) / pathConfigFile;

    return pathConfigFile;
}

void ReadConfigFile(map<string, string>& mapSettingsRet,
                    map<string, vector<string> >& mapMultiSettingsRet)
{
    boost::filesystem::ifstream streamConfig(GetConfigFile());
    if (!streamConfig.good())
        throw missing_safecoin_conf();

    set<string> setOptions;
    setOptions.insert("*");

    for (boost::program_options::detail::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it)
    {
        // Don't overwrite existing settings so command line settings override safecoin.conf
        string strKey = string("-") + it->string_key;
        if (mapSettingsRet.count(strKey) == 0)
        {
            mapSettingsRet[strKey] = it->value[0];
            // interpret nofoo=1 as foo=0 (and nofoo=0 as foo=1) as long as foo not set)
            InterpretNegativeSetting(strKey, mapSettingsRet);
        }
        mapMultiSettingsRet[strKey].push_back(it->value[0]);
    }
    // If datadir is changed in .conf file:
    ClearDatadirCache();
    extern uint16_t BITCOIND_RPCPORT;
    BITCOIND_RPCPORT = GetArg("-rpcport",BaseParams().RPCPort());
}

#ifndef _WIN32
boost::filesystem::path GetPidFile()
{
    boost::filesystem::path pathPidFile(GetArg("-pid", "safecoind.pid"));
    if (!pathPidFile.is_complete())
        pathPidFile = GetDataDir() / pathPidFile;
    return pathPidFile;
}

void CreatePidFile(const boost::filesystem::path &path, pid_t pid)
{
    FILE* file = fopen(path.string().c_str(), "w");
    if (file != nullptr)
    {
        fprintf(file, "%d\n", pid);
        fclose(file);
    }
}
#endif

bool RenameOver(boost::filesystem::path src, boost::filesystem::path dest)
{
#ifdef _WIN32
    return MoveFileExA(src.string().c_str(), dest.string().c_str(),
                       MOVEFILE_REPLACE_EXISTING) != 0;
#else
    int rc = rename(src.string().c_str(), dest.string().c_str());
    return rc == 0;
#endif /* _WIN32 */
}

/**
 * Ignores exceptions thrown by Boost's create_directory if the requested directory exists.
 * Specifically handles case where path p exists, but it wasn't possible for the user to
 * write to the parent directory.
 */
bool TryCreateDirectory(const boost::filesystem::path& p)
{
    try
    {
        return boost::filesystem::create_directory(p);
    } catch (const boost::filesystem::filesystem_error&) {
        if (!boost::filesystem::exists(p) || !boost::filesystem::is_directory(p))
            throw;
    }

    // create_directory didn't create the directory, it had to have existed already
    return false;
}

void FileCommit(FILE *fileout)
{
    fflush(fileout); // harmless if redundantly called
#ifdef _WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(fileout));
    FlushFileBuffers(hFile);
#else
    #if defined(__linux__) || defined(__NetBSD__)
    fdatasync(fileno(fileout));
    #elif defined(__APPLE__) && defined(F_FULLFSYNC)
    fcntl(fileno(fileout), F_FULLFSYNC, 0);
    #else
    fsync(fileno(fileout));
    #endif
#endif
}

bool TruncateFile(FILE *file, unsigned int length) {
#if defined(WIN32)
    return _chsize(_fileno(file), length) == 0;
#else
    return ftruncate(fileno(file), length) == 0;
#endif
}

/**
 * this function tries to raise the file descriptor limit to the requested number.
 * It returns the actual file descriptor limit (which may be more or less than nMinFD)
 */
int RaiseFileDescriptorLimit(int nMinFD) {
#if defined(WIN32)
    return 2048;
#else
    struct rlimit limitFD;
    if (getrlimit(RLIMIT_NOFILE, &limitFD) != -1) {
        if (limitFD.rlim_cur < (rlim_t)nMinFD) {
            limitFD.rlim_cur = nMinFD;
            if (limitFD.rlim_cur > limitFD.rlim_max)
                limitFD.rlim_cur = limitFD.rlim_max;
            setrlimit(RLIMIT_NOFILE, &limitFD);
            getrlimit(RLIMIT_NOFILE, &limitFD);
        }
        return limitFD.rlim_cur;
    }
    return nMinFD; // getrlimit failed, assume it's fine
#endif
}

/**
 * this function tries to make a particular range of a file allocated (corresponding to disk space)
 * it is advisory, and the range specified in the arguments will never contain live data
 */
void AllocateFileRange(FILE *file, unsigned int offset, unsigned int length) {
#if defined(WIN32)
    // Windows-specific version
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(file));
    LARGE_INTEGER nFileSize;
    int64_t nEndPos = (int64_t)offset + length;
    nFileSize.u.LowPart = nEndPos & 0xFFFFFFFF;
    nFileSize.u.HighPart = nEndPos >> 32;
    SetFilePointerEx(hFile, nFileSize, 0, FILE_BEGIN);
    SetEndOfFile(hFile);
#elif defined(MAC_OSX)
    // OSX specific version
    fstore_t fst;
    fst.fst_flags = F_ALLOCATECONTIG;
    fst.fst_posmode = F_PEOFPOSMODE;
    fst.fst_offset = 0;
    fst.fst_length = (off_t)offset + length;
    fst.fst_bytesalloc = 0;
    if (fcntl(fileno(file), F_PREALLOCATE, &fst) == -1) {
        fst.fst_flags = F_ALLOCATEALL;
        fcntl(fileno(file), F_PREALLOCATE, &fst);
    }
    ftruncate(fileno(file), fst.fst_length);
#elif defined(__linux__)
    // Version using posix_fallocate
    off_t nEndPos = (off_t)offset + length;
    posix_fallocate(fileno(file), 0, nEndPos);
#else
    // Fallback version
    // TODO: just write one byte per block
    static const char buf[65536] = {};
    fseek(file, offset, SEEK_SET);
    while (length > 0) {
        unsigned int now = 65536;
        if (length < now)
            now = length;
        fwrite(buf, 1, now, file); // allowed to fail; this function is advisory anyway
        length -= now;
    }
#endif
}

void ShrinkDebugFile()
{
    // Scroll debug.log if it's getting too big
    boost::filesystem::path pathLog = GetDataDir() / "debug.log";
    FILE* file = fopen(pathLog.string().c_str(), "r");
    if (file != nullptr) {
        if (boost::filesystem::file_size(pathLog) > 10 * 1000000)
        {
            // Restart the file with some of the end
            vector <char> vch(200000,0);
            fseek(file, -(long)vch.size(), SEEK_END);
            int nBytes = fread(begin_ptr(vch), 1, vch.size(), file);
            fclose(file);

            file = fopen(pathLog.string().c_str(), "w");
            if (file != nullptr)
            {
                fwrite(begin_ptr(vch), 1, nBytes, file);
                fclose(file);
            }
        }
        fclose(file);
    }
}

#ifdef _WIN32
boost::filesystem::path GetSpecialFolderPath(int nFolder, bool fCreate)
{
    namespace fs = boost::filesystem;

    char pszPath[MAX_PATH] = "";

    if(SHGetSpecialFolderPathA(NULL, pszPath, nFolder, fCreate))
        return fs::path(pszPath);

    LogPrintf("SHGetSpecialFolderPathA() failed, could not obtain requested path.\n");
    return fs::path("");
}
#endif

boost::filesystem::path GetTempPath() {
#if BOOST_FILESYSTEM_VERSION == 3
    return boost::filesystem::temp_directory_path();
#else
    // TODO: remove when we don't support filesystem v2 anymore
    boost::filesystem::path path;
    #ifdef _WIN32
    char pszPath[MAX_PATH] = "";

    if (GetTempPathA(MAX_PATH, pszPath))
        path = boost::filesystem::path(pszPath);
    #else
    path = boost::filesystem::path("/tmp");
    #endif
    if (path.empty() || !boost::filesystem::is_directory(path)) {
        LogPrintf("GetTempPath(): failed to find temp path\n");
        return boost::filesystem::path("");
    }
    return path;
#endif
}

void runCommand(const string& strCommand)
{
    int nErr = ::system(strCommand.c_str());
    if (nErr != 0)
        LogPrintf("runCommand error: system(%s) returned %d\n", strCommand, nErr);
}

void RenameThread(const char* name)
{
#if defined(PR_SET_NAME)
    // Only the first 15 characters are used (16 - NUL terminator)
    ::prctl(PR_SET_NAME, name, 0, 0, 0);
#elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
    pthread_set_name_np(pthread_self(), name);

#elif defined(MAC_OSX)
    pthread_setname_np(name);
#else
    // Prevent warnings for unused parameters...
    (void)name;
#endif
}

void SetupEnvironment()
{
    // On most POSIX systems (e.g. Linux, but not BSD) the environment's locale
    // may be invalid, in which case the "C" locale is used as fallback.
#if !defined(WIN32) && !defined(MAC_OSX) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
    try {
        locale(""); // Raises a runtime error if current locale is invalid
    } catch (const runtime_error&) {
        setenv("LC_ALL", "C", 1);
    }
#endif
    // The path locale is lazy initialized and to avoid deinitialization errors
    // in multithreading environments, it is set explicitly by the main thread.
    // A dummy locale is used to extract the internal default locale, used by
    // boost::filesystem::path, which is then used to explicitly imbue the path.
    locale loc = boost::filesystem::path::imbue(locale::classic());
    boost::filesystem::path::imbue(loc);
}

#ifdef _WIN32
bool SetupNetworking()
{
    // Initialize Windows Sockets
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    return ret == NO_ERROR && LOBYTE(wsadata.wVersion ) == 2 && HIBYTE(wsadata.wVersion) == 2;
}
#endif

void SetThreadPriority(int nPriority)
{
#ifdef _WIN32
    SetThreadPriority(GetCurrentThread(), nPriority);
#else // _WIN32
    #ifdef PRIO_THREAD
    setpriority(PRIO_THREAD, 0, nPriority);
    #else // PRIO_THREAD
    setpriority(PRIO_PROCESS, 0, nPriority);
    #endif // PRIO_THREAD
#endif // _WIN32
}

string PrivacyInfo()
{
    return "\n" +
           FormatParagraph(strprintf(_("In order to ensure you are adequately protecting your privacy when using Safecoin, please see <%s>."),
                                     "https://z.cash/support/security/")) + "\n";
}

string LicenseInfo()
{
    return "\n" +
           FormatParagraph(strprintf(_("Copyright (C) 2009-%i The Bitcoin Core Developers"), COPYRIGHT_YEAR)) + "\n" +
           FormatParagraph(strprintf(_("Copyright (C) 2015-%i The Zcash Developers"), COPYRIGHT_YEAR)) + "\n" +
           FormatParagraph(strprintf(_("Copyright (C) 2015-%i jl777 and SuperNET developers"), COPYRIGHT_YEAR)) + "\n" +
           FormatParagraph(strprintf(_("Copyright (C) 2018-%i The Verus developers"), COPYRIGHT_YEAR)) + "\n" +
           "\n" +
           FormatParagraph(_("This is experimental software.")) + "\n" +
           "\n" +
           FormatParagraph(_("Distributed under the MIT software license, see the accompanying file COPYING or <http://www.opensource.org/licenses/mit-license.php>.")) + "\n" +
           "\n" +
           FormatParagraph(_("This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit <https://www.openssl.org/> and cryptographic software written by Eric Young.")) +
           "\n";
}

int GetNumCores()
{
    return boost::thread::physical_concurrency();
}

