VerusCoin Command Line Tools v0.4.0c
Contents:
safecoind - VerusCoin's enhanced Safecoin daemon.
safecoin-cli - VerusCoin's enhanced Safecoin command line utility.
verus - wrapper for safecoin-cli that applies the command to the VRSC coin
verusd - wrapper for safecoind that sets the VerusCoin parameters to defaults properly
fetch_params.sh - utility to download the zcash parameters needed to start the VerusCoin command line tools and scripts
lib*.dylib - assorted dynamic libraries, dependencies needed by fetch-params.sh, safecoind and/or safecoin-cli

Command line tools are run from the terminal. You can launch the terminal on a Mac by using the Finder, selecting Applications and from that select Utilities, finally selecting Terminal from the Utilities folder.
You will need to switch to the directory you extracted the verus-cl into. If you extracted it in the Download folder then the change directory command is
cd ~/Downloads/verus-cli
The first time on a new system you will need to run ./fetch-params before using safecoind or verusd.

Run ./verusd to launch safecoind, and use verus to run commands such as:
./verus stop
Which signals safecoind (if it is running) to stop running.
