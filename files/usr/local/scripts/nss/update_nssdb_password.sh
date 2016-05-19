#!/bin/bash
#
#
#
clean_up(){ 
  if [ -d $tmpdir ]; then
    rm -rf $tmpdir
  fi
}

umask 0077

if [ "$#" -ne 4 ]; then
    echo "Illegal number of parameters.  Expecting 4 got $#"
    exit -5
fi

export PATH="/usr/bin:/usr/sbin:/bin:/sbin"
token="$4"
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
modutil -force -changepw "${token}" -dbdir "sql:${ipsecdir}" -newpwfile ${tmpdir}/np -pwfile ${tmpdir}/op > ${tmpdir}/modutil.output
rv=$?
if [ $rv !=  0 ]; then
  message="`cat ${tmpdir}/modutil.output`"
  echo "modutil ${i}" ${message} $rv
  clean_up
  exit $rv
fi

clean_up
exit 0

