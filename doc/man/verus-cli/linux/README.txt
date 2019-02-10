VerusCoin Command Line Tools v0.4.0c

Contents:
safecoind - VerusCoin's enhanced Safecoin daemon
safecoin-cli - VerusCoin's Safecoin command line utility
verus - wrapper for safecoin-cli that applies the command to the VRSC coin
verusd - wrapper for safecoind that sets the VerusCoin parameters to defaults properly

The first time on a new system you will need to run ./fetch-params before using safecoind or verusd.

Run ./verusd to launch safecoind, and use verus to run commands such as:
./verus stop
Which signals safecoind (if it is running) to stop running.
