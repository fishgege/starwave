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

if [[ -z "$STARWAVE_BENCHMARK_ROUTER_ENTITY" ]]
then
    echo "$preamble \$STARWAVE_BENCHMARK_ROUTER_ENTITY not set"
    exit 1
fi

if [[ -z "$STARWAVE_BENCHMARK_BANKROLL" ]]
then
    echo "$preamble \$STARWAVE_BENCHMARK_BANKROLL not set"
    exit 2
fi

drvk=$(bw2_vk_from_entity_file $STARWAVE_BENCHMARK_ROUTER_ENTITY)

# Create namespace
if [[ -f .ns.done ]]
then
    echo "$preamble Namespace already set up"
    nsvk=$(starwave_vk_from_entity_file ns.ent)
else
    echo "$preamble Setting up namespace..."
    starwave mke -o ns.ent -b $STARWAVE_BENCHMARK_BANKROLL
    nsvk=$(starwave_vk_from_entity_file ns.ent)
    starwave mkdroffer --dr $STARWAVE_BENCHMARK_ROUTER_ENTITY --ns $nsvk -b $STARWAVE_BENCHMARK_BANKROLL
    starwave adro --dr $drvk --ns ns.ent -b $STARWAVE_BENCHMARK_BANKROLL
    echo $nsvk > .ns.done
fi

# Create entity for publish benchmark
if [[ -f .publish.done ]]
then
    echo "$preamble Publish benchmark already set up"
    publishvk=$(starwave_vk_from_entity_file publish.ent)
else
    echo "$preamble Creating entity for publish benchmark..."
    starwave mke -o publish.ent -b $STARWAVE_BENCHMARK_BANKROLL
    echo "$preamble Waiting one minute for the registry to update..."
    sleep 60
    publishvk=$(starwave_vk_from_entity_file publish.ent)
    starwave mkd -f ns.ent -t $publishvk -x "P" -u "$nsvk/a/b/c/d/e/f" -o nstopublish.dot -b $STARWAVE_BENCHMARK_BANKROLL
    echo $publishvk > .publish.done
fi
