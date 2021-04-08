#!/bin/bash
#echo $NVM_BIN
#echo $SNYK_TOKEN
#echo " "

if [[ "$DMSCAN_ENV" == "DEV" ]]; then
  $NVM_BIN/node $NVM_BIN/snyk auth $SNYK_TOKEN >/dev/null 2>&1
  $NVM_BIN/node $NVM_BIN/snyk container test $1 --json
else
  snyk auth $SNYK_TOKEN >/dev/null 2>&1
  snyk container test $1 --json
fi
