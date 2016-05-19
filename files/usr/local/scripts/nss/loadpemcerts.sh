#!/bin/sh
#
#
#
clean_up(){ 
  if [[ -d $tmpdir ]]; then
    rm -rf $tmpdir
  fi
}

error() {
  local parent_lineno="$1"
  local message="$2"
  local code="${3:-1}"
  if [[ -n "$message" ]] ; then
    echo "Error on or near line ${parent_lineno}: ${message}; exiting with status ${code}"
  else
    echo "Error on or near line ${parent_lineno}; exiting with status ${code}"
  fi
  clean_up
  exit "${code}"
}

trap 'error ${LINENO}' ERR INT TERM EXIT

umask 0077

if [[ "$#" -ne 3 ]]; then
    echo "Illegal number of parameters"
    exit -3
fi
nickname=$3
export PATH="$5:/usr/bin:/usr/sbin:/bin:/sbin"
cert=$2
key=$1
ipsecdir="$4"


if [[ ! -d $ipsecdir ]]; then
  echo "No directory $ipsecdir found"
  exit -1
fi

if [[ ! -f $cert || ! -f $key ]]; then
  echo "Could not find either the cert:  $cert or the key $key"
  exit -2
fi


# Create Temp Working Dir
day=`date +%y%m%d%H%M%S`
tmpdir=$ipsecdir/loadservercert$day
tmppwd=""

if  [[ -d $tmpdir ]]; then
  echo "temp dir $tmpdir already exists."
  exit  10
fi

mkdir -p $tmpdir

# Determine what fips mode the database is in.
name=`echo $cert | cut -f2 -d/ | cut -f1 -d.`
openssl pkcs12 -export  -in $cert -inkey  $key -out $tmpdir/${name}.p12  -passout pass:${tmppwd} 
rv=$?

if [[ $rv != 0 ]]; then 
    message="error creating pk12 cert"
    parent=$0
    error $parent $message $rv
    exit $rv
fi
# Determine the old password

nss_pwdfile="${ipsecdir}/nsspassword"

#insert the P12 cert into the database
if [[ ${name} == "" ]] ; then
  $name=`pk12util -l  $tmpdir/${name}.p12  -W $tmppwd  | grep -m1 "Friendly Name:"| cut -f2 -d:`
fi
pk12util -i $tmpdir/${name}.p12 -W $tmppwd -d sql:${ipsecdir}" -k $nss_pwdfile -n $name 2> $(tmpdir}/p12error.
rv=$?

clean_up
if [[ $rv !=  0 ]]; then
  parent="pk12util" 
  message="Error loading cert $cert into NSS $ipsecdir
  error $parent ${message} $rv
else
  exit 0
fi

