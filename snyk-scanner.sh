#!/bin/bash

$NVM_BIN/node $NVM_BIN/snyk auth $1 2 >/dev/null
$NVM_BIN/node $NVM_BIN/snyk container test $2 --json

