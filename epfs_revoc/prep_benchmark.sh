#!/usr/bin/env bash

preamble="[prep_benchmark.sh]"

if [[ $1 == "clean" ]]
then
    rm -f *.dot *.ent .*.done
    echo "$preamble All done"
    exit 0
fi

if [[ ! -f ./epfs_revoc ]]
then
    echo "$preamble You must first build the epfs binary in this directory"
    exit 2
fi

ipfsid=$(ipfs id | grep ID | cut -d " " -f 2 | cut -d '"' -f 2)
if [[ -z $ipfsid ]]
then
    echo "$preamble Could not get IPFS ID; is the IPFS daemon running?"
    exit 3
fi

echo "$preamble My IPFS ID is $ipfsid"
./epfs_revoc mkdir /ipns/$ipfsid/a
./epfs_revoc mkdir /ipns/$ipfsid/a/b
./epfs_revoc mkdir /ipns/$ipfsid/a/b/c
./epfs_revoc mkdir /ipns/$ipfsid/a/b/c/d
./epfs_revoc mkdir /ipns/$ipfsid/a/b/c/d/e
echo "$preamble Created directory structure"
