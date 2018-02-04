#!/usr/bin/env bash

preamble="[prep_benchmark.sh]"

if [[ $1 == "clean" ]]
then
    rm -f *.dot *.ent .*.done
    echo "$preamble All done"
    exit 0
fi

bw2_vk_from_entity_file() {
    ENTITY_FILE=$1
    bw2 i $ENTITY_FILE | grep VK | cut -d ' ' -f 4
}

starwave_vk_from_entity_file() {
    ENTITY_FILE=$1
    starwave i $ENTITY_FILE | grep VK | cut -d ' ' -f 4
}

if [[ ! -f ../swbind/ns.ent ]]
then
    echo "$preamble You must first run prep_benchmark.sh in the swbind directory"
    exit 1
fi

if [[ ! -f ./epfs ]]
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
./epfs mkdir /ipns/$ipfsid/a
./epfs mkdir /ipns/$ipfsid/a/b
./epfs mkdir /ipns/$ipfsid/a/b/c
./epfs mkdir /ipns/$ipfsid/a/b/c/d
./epfs mkdir /ipns/$ipfsid/a/b/c/d/e
echo "$preamble Created directory structure"
