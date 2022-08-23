#!/bin/bash

GREEN='\033[0;01;32m'
RED='\033[0;01;31m'
YELLOW='\033[0;01;33m'
NC='\033[0m'

## error handling

error() {
  echo -e "${RED}[!] ERROR: $1${NC}";
}

warn() {
  echo -e "${YELLOW}[!] WARNING: $1${NC}";
}

okay() {
  echo -e "${GREEN}[*] SUCCESS: $1${NC}";
}

errexit()      { error "$1"; exit 1; }
warnexit()     { warn  "$1"; exit 0; }
warncontinue() { warn "$1"; }
errnull()      {             exit 2; } # reserved for 'make' (always ret 2 on errors)
errtimeout()   { error "$1"; exit 3; }
errfailure()   { error "$1"; exit 4; }
okexit()       { okay  "$1"; exit 0; }
okcontinue()   { okay  "$1";         }

## kernel version checks

kern_version() {
  _oper=$1; _version=$2; _notfatal=$3;
  _given=$(($(echo $_version | sed 's:\.::g')))
  _current=$(($(uname -r | cut -d'.' -f1,2 | sed 's:\.::g')))

  [[ "$_version" == "" ]] && errexit "no kernel version given"

  _opergood=0

  case $_oper in
    lt)
      [[ $_current -lt $_given ]] && _opergood=1
      ;;
    le)
      [[ $_current -le $_given ]] && _opergood=1
      ;;
    ge)
      [[ $_current -ge $_given ]] && _opergood=1
      ;;
    gt)
      [[ $_current -gt $_given ]] && _opergood=1
      ;;
    *)
      errexit "wrong oper"
      ;;
  esac

  if [[ $_opergood -ne 1 ]]; then
    if [[ $_notfatal -eq 1 ]]; then
        warncontinue "kernel $_current not $_oper than $_given"
    else
        errexit "kernel $_current not $_oper than $_given"
    fi
  fi
}

## checks

check_build() {
  [[ "$TEST" == "" ]] && errexit "test is undefined"
  [[ ! -z $TEST ]] || errexit "run make first"
}

check_ppid() {
  _ppid=$(ps -o ppid= $$);
  _pppid=$(ps -o ppid= $_ppid);
  _ppppid=$(ps -o ppid= $_pppid);

  _comm=$(ps -o comm= $_ppid);
  _pcomm=$(ps -o comm= $_pppid);
  _ppcomm=$(ps -o comm= $_ppppid);

  if [[ $_comm != make && $_pcomm != make && $_ppcomm != make ]]; then
    errexit "do a 'make run' instead";
  fi
}

# exec functions

execfg() {
  _timeout=$1; shift;
  _what=$1; shift;
  _arg=$@

  [[ "$_timeout " == "" ]] && errexit "timeout not set"
  [[ "$_what " == "" ]] && errexit "background task not set"
  [[ ! -x "$_what" ]] && errexit "$_what not executable"

  timeout $_timeout $_what $_arg; _retcode=$?;

  [ $_retcode -eq 124 ] && errtimeout "selftest timeout"
}

_bigtimeout=0

execbg() {
  _timeout=$1; shift;
  _what=$1; shift;
  _arg=$@

  [[ "$_timeout " == "" ]] && errexit "timeout not set"
  [[ "$_what " == "" ]] && errexit "background task not set"
  [[ ! -x "$_what" ]] && errexit "$_what not executable"

  # always wait for the biggest timeout (at the end)
  [ $_timeout -gt $_bigtimeout ] && _bigtimeout=$_timeout

  timeout $_timeout $_what $_arg &
}

waitbg() {
  echo "waiting for background tasks"
  sleep $_bigtimeout
}

## test functions

test_exec() {
  execfg $TIMEOUT $TEST
}

test_step() {
  case $_retcode in
  0)
    okcontinue "all good"
    ;;
  *)
    errfailure "test error"
    ;;
esac
}

test_finish() {
  case $_retcode in
  0)
    okexit "all good"
    ;;
  *)
    errfailure "test error"
    ;;
esac
}
