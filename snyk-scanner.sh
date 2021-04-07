#!/bin/bash
#echo $NVM_BIN
#echo $SNYK_TOKEN
#echo " "
$NVM_BIN/node $NVM_BIN/snyk auth $SNYK_TOKEN 2>/dev/null
$NVM_BIN/node $NVM_BIN/snyk container test $1 --json

