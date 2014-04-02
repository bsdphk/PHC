#!/bin/sh
#
# This is the script which was used to create this git repos
# from the submission files.
#
# It should be pretty generic "modern UNIX" but has only ever
# been run on FreeBSD yet.
#
# Authored by: Poul-Henning Kamp <phk@FreeBSD.org>
#
# This script is in the public domain

set -e

if false ; then
	wget --no-check-certificate -m -np \
		'https://password-hashing.net/candidates.html'
fi

rm -rf Git

mkdir -p Git

for i in password-hashing.net/submissions/*tar.gz
do
	tar -C Git -xzf $i
done

cd Git

# Be consistent
mv battcrypt-v0 Battcrypt-v0
mv yescrypt-v0 Yescrypt-v0

# Remove embedded Git repositories
find . -name '.git*' -print0 | xargs -0 rm -rf 

# Eliminate original distribution files
rm -f */*.gz
rm -f */*.zip
rm -f */*.bz2
rm -f */*.tar
rm -f */*.tgz

# Make filenames "safe"
for x in d f
do
	find . -type $x -print | while read fi
	do
		fo=`echo $fi | sed 's/[^a-zA-Z0-9._\/+~-]/_/g'`
		if [ "$fi" != "$fo" ] ; then
			mv "$fi" $fo
		fi
	done
done

# Remove hidden files and directories
find . -name '.[^.]*' -print0 | xargs -0 rm -rf

if true ; then
	for d in [A-Z]*
	do
		dd=`basename $d -v0`
		mv $d ${d}_
		mkdir $dd
		(
		cd ${d}_
		for f in *
		do
			if [ -f $f ] ; then
				mv $f ../$dd
			else
				mv $f/* ../$dd
				rmdir $f
			fi
		done
		)
		rmdir ${d}_
	done
fi


# CRLF -> LF
find . -type f -print | xargs file | grep CRLF | sed 's/:.*//' | while read f
do
	sed -i "" 's///g' $f
done

# Find identical files
if false ; then
	find . -type f -print | xargs md5 > __

	cat __ | sed 's/.* //' | sort | uniq -c | sort -rn | awk '$1 > 1 {print $2}' | while read md5
	do

		echo ""
		grep $md5 __
	done
fi

# Final cleanup
find . -name '*.pyc' -print | xargs rm
find . -name '*.o' -print | xargs rm
find . -name '*.so' -print | xargs rm

rm -f OmegaCrypt-v0/nettle-chacha/testsuite/test-chacha

# find . -type f -print | sort | xargs file > index.txt

