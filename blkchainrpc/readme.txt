It takes more than two minute to generate a zkSNARK proof.

Remember to wait for 6 blks after generating a new transaction

To set up, run the following steps:
1. make start
2. make generate BLOCKS=200
3. make getaccountaddress2
// Take the output of last cmd as "addr"
4. make sendtoaddress ADDRESS=addr AMOUNT=500
5. bash mining.sh

Then you can start test.

To stop the network, just use:
make stop
make clean
