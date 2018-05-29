BITCOIND=zcashd
BITCOINCLI=zcash-cli
B1_FLAGS=
B2_FLAGS=
B3_FLAGS=
B1=-datadir=./miner $(B1_FLAGS)
B2=-datadir=./server $(B2_FLAGS)
B3=-datadir=./client $(B3_FLAGS)
BLOCKS=1
ADDRESS=
ACCOUNT=
AMOUNT=
ACCOUNT=
HASH=
HEIGHT=
STRING=
BOOL=true
CONFIRMATIONS=0
EMPTY=true
WATCHONLY=false
FROMADDRESS=
TOADDRESS=
MEMO=
OPID=
STATUS=
TXID=
MSG=""

start:
	$(BITCOIND) $(B1) -daemon
	$(BITCOIND) $(B2) -daemon
	$(BITCOIND) $(B3) -daemon

addnode1:
	$(BITCOINCLI) $(B1) addnode $(ADDRESS) onetry

addnode2:
	$(BITCOINCLI) $(B2) addnode $(ADDRESS) onetry

addnode3:
	$(BITCOINCLI) $(B3) addnode $(ADDRESS) onetry

getaddednodeinfo:
	$(BITCOINCLI) $(B1) getaddednodeinfo $(BOOL)
	$(BITCOINCLI) $(B2) getaddednodeinfo $(BOOL)
	$(BITCOINCLI) $(B3) getaddednodeinfo $(BOOL)

generate:
	$(BITCOINCLI) $(B1) generate $(BLOCKS)

generate1:
	$(BITCOINCLI) $(B1) generate $(BLOCKS)

generate2:
	$(BITCOINCLI) $(B2) generate $(BLOCKS)

generate3:
	$(BITCOINCLI) $(B3) generate $(BLOCKS)

getblockcount:
	$(BITCOINCLI) $(B1) getblockcount
	$(BITCOINCLI) $(B2) getblockcount
	$(BITCOINCLI) $(B3) getblockcount

gettransaction:
	$(BITCOINCLI) $(B1) gettransaction $(HASH)
	$(BITCOINCLI) $(B2) gettransaction $(HASH)
	$(BITCOINCLI) $(B3) gettransaction $(HASH)

gettransaction1:
	$(BITCOINCLI) $(B1) gettransaction $(HASH)

gettransaction2:
	$(BITCOINCLI) $(B2) gettransaction $(HASH)

gettransaction3:
	$(BITCOINCLI) $(B3) gettransaction $(HASH)

getrawtransaction:
	$(BITCOINCLI) $(B1) getrawtransaction $(HASH) 1
	$(BITCOINCLI) $(B2) getrawtransaction $(HASH) 1
	$(BITCOINCLI) $(B3) getrawtransaction $(HASH) 1

getrawtransaction1:
	$(BITCOINCLI) $(B1) getrawtransaction $(HASH) 1

getrawtransaction2:
	$(BITCOINCLI) $(B2) getrawtransaction $(HASH) 1

getrawtransaction3:
	$(BITCOINCLI) $(B3) getrawtransaction $(HASH) 1

z_listoperationids:
	$(BITCOINCLI) $(B1) z_listoperationids $(STATUS)
	$(BITCOINCLI) $(B2) z_listoperationids $(STATUS)
	$(BITCOINCLI) $(B3) z_listoperationids $(STATUS)

z_listoperationids1:
	$(BITCOINCLI) $(B1) z_listoperationids $(STATUS)

z_listoperationids2:
	$(BITCOINCLI) $(B2) z_listoperationids $(STATUS)

z_listoperationids3:
	$(BITCOINCLI) $(B3) z_listoperationids $(STATUS)

z_exportviewingkey1:
	$(BITCOINCLI) $(B1) z_exportviewingkey $(ADDRESS)

z_exportviewingkey2:
	$(BITCOINCLI) $(B2) z_exportviewingkey $(ADDRESS)

z_exportviewingkey3:
	$(BITCOINCLI) $(B3) z_exportviewingkey $(ADDRESS)

z_importviewingkey1:
	$(BITCOINCLI) $(B1) z_importviewingkey $(HASH)

z_importviewingkey2:
	$(BITCOINCLI) $(B2) z_importviewingkey $(HASH)

z_importviewingkey3:
	$(BITCOINCLI) $(B3) z_importviewingkey $(HASH)

z_gettotalbalance:
	$(BITCOINCLI) $(B1) z_gettotalbalance
	$(BITCOINCLI) $(B2) z_gettotalbalance
	$(BITCOINCLI) $(B3) z_gettotalbalance

z_listaddresses1:
	$(BITCOINCLI) $(B1) z_listaddresses

z_listaddresses2:
	$(BITCOINCLI) $(B2) z_listaddresses

z_listaddresses3:
	$(BITCOINCLI) $(B3) z_listaddresses

z_listreceivedbyaddress1:
	$(BITCOINCLI) $(B1) z_listreceivedbyaddress $(ADDRESS)

z_listreceivedbyaddress2:
	$(BITCOINCLI) $(B2) z_listreceivedbyaddress $(ADDRESS)

z_listreceivedbyaddress3:
	$(BITCOINCLI) $(B3) z_listreceivedbyaddress $(ADDRESS)

z_getpaymentdisclosure1:
	$(BITCOINCLI) $(B1) z_getpaymentdisclosure $(TXID) 0 0 $(MSG)

z_getpaymentdisclosure2:
	$(BITCOINCLI) $(B2) z_getpaymentdisclosure $(TXID) 0 0 $(MSG)

z_getpaymentdisclosure3:
	$(BITCOINCLI) $(B3) z_getpaymentdisclosure $(TXID) 0 0 $(MSG)

z_validatepaymentdisclosure1:
	$(BITCOINCLI) $(B1) z_validatepaymentdisclosure $(HASH)

z_validatepaymentdisclosure2:
	$(BITCOINCLI) $(B2) z_validatepaymentdisclosure $(HASH)

z_validatepaymentdisclosure3:
	$(BITCOINCLI) $(B3) z_validatepaymentdisclosure $(HASH)

listreceivedbyaddress:
	$(BITCOINCLI) $(B1) listreceivedbyaddress $(CONFIRMATIONS) $(EMPTY) $(WATCHONLY)
	$(BITCOINCLI) $(B2) listreceivedbyaddress $(CONFIRMATIONS) $(EMPTY) $(WATCHONLY)
	$(BITCOINCLI) $(B3) listreceivedbyaddress $(CONFIRMATIONS) $(EMPTY) $(WATCHONLY)

getblockhash:
	$(BITCOINCLI) $(B1) getblockhash $(HEIGHT)
	$(BITCOINCLI) $(B2) getblockhash $(HEIGHT)
	$(BITCOINCLI) $(B3) getblockhash $(HEIGHT)

getblock:
	$(BITCOINCLI) $(B1) getblock $(HASH)
	$(BITCOINCLI) $(B2) getblock $(HASH)
	$(BITCOINCLI) $(B3) getblock $(HASH)

signrawtransaction:
	$(BITCOINCLI) $(B1) signrawtransaction $(HASH)

signrawtransaction1:
	$(BITCOINCLI) $(B1) signrawtransaction $(HASH)

signrawtransaction2:
	$(BITCOINCLI) $(B2) signrawtransaction $(HASH)

signrawtransaction3:
	$(BITCOINCLI) $(B3) signrawtransaction $(HASH)

decoderawtransaction:
	$(BITCOINCLI) $(B1) decoderawtransaction $(HASH)

decoderawtransaction1:
	$(BITCOINCLI) $(B1) decoderawtransaction $(HASH)

decoderawtransaction2:
	$(BITCOINCLI) $(B2) decoderawtransaction $(HASH)

decoderawtransaction3:
	$(BITCOINCLI) $(B3) decoderawtransaction $(HASH)

sendrawtransaction:
	$(BITCOINCLI) $(B1) sendrawtransaction $(HASH)

sendrawtransaction1:
	$(BITCOINCLI) $(B1) sendrawtransaction $(HASH)

sendrawtransaction2:
	$(BITCOINCLI) $(B2) sendrawtransaction $(HASH)

sendrawtransaction3:
	$(BITCOINCLI) $(B3) sendrawtransaction $(HASH)

getinfo:
	$(BITCOINCLI) $(B1) getinfo
	$(BITCOINCLI) $(B2) getinfo
	$(BITCOINCLI) $(B3) getinfo

getrawmempool:
	$(BITCOINCLI) $(B1) getrawmempool $(BOOL)
	$(BITCOINCLI) $(B2) getrawmempool $(BOOL)
	$(BITCOINCLI) $(B3) getrawmempool $(BOOL)

getpeerinfo:
	$(BITCOINCLI) $(B1) getpeerinfo
	$(BITCOINCLI) $(B2) getpeerinfo
	$(BITCOINCLI) $(B3) getpeerinfo

getnetworkinfo:
	$(BITCOINCLI) $(B1) getnetworkinfo
	$(BITCOINCLI) $(B2) getnetworkinfo
	$(BITCOINCLI) $(B3) getnetworkinfo

getaccountaddress1:
	$(BITCOINCLI) $(B1) getaccountaddress "$(ACCOUNT)"

getaccountaddress2:
	$(BITCOINCLI) $(B2) getaccountaddress "$(ACCOUNT)"

getaccountaddress3:
	$(BITCOINCLI) $(B3) getaccountaddress "$(ACCOUNT)"

getnewaddress1:
	$(BITCOINCLI) $(B1) getnewaddress "$(ACCOUNT)"

getnewaddress2:
	$(BITCOINCLI) $(B2) getnewaddress "$(ACCOUNT)"

getnewaddress3:
	$(BITCOINCLI) $(B3) getnewaddress "$(ACCOUNT)"

z_getnewaddress 	:
	$(BITCOINCLI) $(B1) z_getnewaddress
	$(BITCOINCLI) $(B2) z_getnewaddress
	$(BITCOINCLI) $(B3) z_getnewaddress

z_getnewaddress1:
	$(BITCOINCLI) $(B1) z_getnewaddress

z_getnewaddress2:
	$(BITCOINCLI) $(B2) z_getnewaddress

z_getnewaddress3:
	$(BITCOINCLI) $(B3) z_getnewaddress

importaddress:
	$(BITCOINCLI) $(B1) importaddress $(ADDRESS) "" true
	$(BITCOINCLI) $(B2) importaddress $(ADDRESS) "" true
	$(BITCOINCLI) $(B3) importaddress $(ADDRESS) "" true

importaddress1:
	$(BITCOINCLI) $(B1) importaddress $(ADDRESS) "" true

importaddress2:
	$(BITCOINCLI) $(B2) importaddress $(ADDRESS) "" true

importaddress3:
	$(BITCOINCLI) $(B3) importaddress $(ADDRESS) "" true

sendtoaddress:
	$(BITCOINCLI) $(B1) sendtoaddress $(ADDRESS) $(AMOUNT)

sendtoaddress1:
	$(BITCOINCLI) $(B1) sendtoaddress $(ADDRESS) $(AMOUNT)

sendtoaddress2:
	$(BITCOINCLI) $(B2) sendtoaddress $(ADDRESS) $(AMOUNT)

sendtoaddress3:
	$(BITCOINCLI) $(B3) sendtoaddress $(ADDRESS) $(AMOUNT)

z_sendmany1:
	$(BITCOINCLI) $(B1) z_sendmany $(FROMADDRESS) '[{"address": "$(TOADDRESS)", "amount": $(AMOUNT), "memo": "$(MEMO)"}]'

z_sendmany2:
	$(BITCOINCLI) $(B2) z_sendmany $(FROMADDRESS) '[{"address": "$(TOADDRESS)", "amount": $(AMOUNT), "memo": "$(MEMO)"}]'

z_sendmany3:
	$(BITCOINCLI) $(B3) z_sendmany $(FROMADDRESS) '[{"address": "$(TOADDRESS)", "amount": $(AMOUNT), "memo": "$(MEMO)"}]'

z_getoperationresult1:
	$(BITCOINCLI) $(B1) z_getoperationresult '["$(OPID)"]'

z_getoperationresult2:
	$(BITCOINCLI) $(B2) z_getoperationresult '["$(OPID)"]'

z_getoperationresult3:
	$(BITCOINCLI) $(B3) z_getoperationresult '["$(OPID)"]'

z_getoperationstatus1:
	$(BITCOINCLI) $(B1) z_getoperationstatus '["$(OPID)"]'

z_getoperationstatus2:
	$(BITCOINCLI) $(B2) z_getoperationstatus '["$(OPID)"]'

z_getoperationstatus3:
	$(BITCOINCLI) $(B3) z_getoperationstatus '["$(OPID)"]'

address:
	$(BITCOINCLI) $(B1) getnewaddress $(ACCOUNT)

stop:
	$(BITCOINCLI) $(B1) stop
	$(BITCOINCLI) $(B2) stop
	$(BITCOINCLI) $(B3) stop

stop1:
	$(BITCOINCLI) $(B1) stop

stop2:
	$(BITCOINCLI) $(B2) stop

stop3:
	$(BITCOINCLI) $(B3) stop

clean:
	rm -rf ./miner/regtest
	rm -rf ./server/regtest
	rm -rf ./client/regtest

cleantestnet:
		rm -rf ./miner/testnet3
		rm -rf ./server/testnet3
		rm -rf ./client/testnet3
