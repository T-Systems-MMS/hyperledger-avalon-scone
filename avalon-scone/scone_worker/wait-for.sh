#!/bin/sh

# Copyright 2020 Mujtaba Idrees
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

TIMEOUT=15
QUIET=0

echoerr() {
  if [ "$QUIET" -ne 1 ]; then printf "%s\n" "$*" 1>&2; fi
}

usage() {
  exitcode="$1"
  cat << USAGE >&2
Usage:
  $cmdname host:port [-t timeout] [-- command args]
  -q | --quiet                        Do not output any status messages
  -t TIMEOUT | --timeout=timeout      Timeout in seconds, zero for no timeout
  -- COMMAND ARGS                     Execute command with args after the test finishes
USAGE
  exit "$exitcode"
}

wait_for() {
#  for i in `seq $TIMEOUT` ; do
# never timeout
  while true ; do
#    nc -z "$HOST" "$PORT" > /dev/null 2>&1
    result=$(curl -k $HOST --stderr - | grep "encryption_key_signature")
    if [[ ${#result} -gt 0 ]] ; then
        exec "$@"
        exit 0
    fi
    sleep 2
  done
#  echo "Operation timed out" >&2
#  exit 1
}

while [ $# -gt 0 ]
do
  case "$1" in
    *:* )
    HOST=$1
    shift 1
    ;;
    -q | --quiet)
    QUIET=1
    shift 1
    ;;
    -t)
    TIMEOUT="$2"
    if [ "$TIMEOUT" = "" ]; then break; fi
    shift 2
    ;;
    --timeout=*)
    TIMEOUT="${1#*=}"
    shift 1
    ;;
    --)
    shift
    break
    ;;
    --help)
    usage 0
    ;;
    *)
    echoerr "Unknown argument: $1"
    usage 1
    ;;
  esac
done

if [ "$HOST" = "" ]; then
  echoerr "Error: you need to provide a url to test."
  usage 2
fi

wait_for "$@"
