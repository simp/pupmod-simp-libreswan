#!/bin/bash
#
#
#
clean_up(){ 
  if [ -d $tmpdir ]; then
    rm -rf $tmpdir
  fi
}

error() {
  local parent_lineno="$1"
  local message="$2"
  local code="${3:-1}"
  if [ -n "$message" ] ; then
    echo "Error on or near line ${parent_lineno}: ${message}; exiting with status ${code}"
  else
    echo "Error on or near line ${parent_lineno}; exiting with status ${code}"
  fi
  clean_up
  exit "${code}"
}

trap 'error ${LINENO}' ERR INT TERM EXIT

umask 0077

if [ "$#" -ne 5 ]; then
    echo "Illegal number of parameters"
    exit -5
fi

export PATH="$5:/usr/bin:/usr/sbin:/bin:/sbin"
tokens=$4
oldpasswd="$3"
passwd="$2"
ipsecdir="$1"

if [ ! -d $ipsecdir ]; then
  echo "No directory $ipsecdir found"
  exit -1
fi

if [ $passwd == "" ]; then
  echo "No Password"
  exit -2
fi

# Create Temp Working Dir
day=`date +%y%m%d%H%M%S`
tmpdir=$ipsecdir/$day

if  [ -d $tmpdir ]; then
  echo "temp dir $tmpdir already exists."
  exit  10
fi

mkdir -p $tmpdir
# Determine the old password
case $oldpasswd in
[nN][oO][nN][eE]) 
  echo "" > $tmpdir/op
  ;;
*) 
  echo $oldpasswd > $tmpdir/op
  ;;
esac

echo $passwd > $tmpdir/np
for i in ${tokens[@]}; do
   modutil -force -changepw "${i}" -dbdir "sql:${ipsecdir}" -newpwfile ${tmpdir}/np -pwfile ${tmpdir}/op > ${tmpdir}/modutil.output
   rv=$?
   if [ $rv !=  0 ]; then
     message="`cat ${tmpdir}/modutil.output`"
     error "modutil ${i}" ${message} $rv
   fi
done

clean_up
exit 0

