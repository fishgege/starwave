package blkchainrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func startHelper(t *testing.T, cli *Zcash_cli) {
	err := Start(cli)
	if err != nil {
		t.Fatal(err)
	}
}

func gettaddrHelper(t *testing.T, cli *Zcash_cli) {
	err := GetTAddr(cli)
	if err != nil {
		t.Fatal(err)
	}
}

func getzaddrHelper(t *testing.T, cli *Zcash_cli) {
	err := GetZAddr(cli)
	if err != nil {
		t.Fatal(err)
	}
}

func sleepHelper(t *testing.T, time string) {
	cmd := exec.Command("sleep", time)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		t.Fatal(err)
	}
}

func sendmsgHelper(t *testing.T, miner *Zcash_cli, server *Zcash_cli, client *Zcash_cli, msg string) string {
	err := SendToAddr(server, server.Taddr, "6")
	if err != nil {
		t.Fatal(err)
	}

	err = GenerateBlk(miner, "6")
	if err != nil {
		t.Fatal(err)
	}
	sleepHelper(t, "15")

	var opid string
	opid, err = ZSendMany(server, server.Taddr, server.Zaddr, "1", msg, "4")
	if err != nil {
		t.Fatal(err)
	}

	var out string
	out, err = ZGetOperationStatus(server, opid)
	if err != nil {
		t.Fatal(err)
	}

	println(out)
	return out
}

func checkHelper(t *testing.T, cli *Zcash_cli) {
	out, err := ListReceivedByVAddr(cli)
	if err != nil {
		t.Fatal(err)
	}

	//	println("begin checker!")
	//	println(string(out))

	var txs []ZTransaction
	txs, err = GetZTransaction(out)
	if err != nil {
		t.Fatal(err)
	}

	//println(len(txs))
	//println("tx0:" + txs[0].Memo)
	//println("tx1:" + txs[1].Memo)
	if (!strings.Contains(txs[0].Memo, "6666") && !strings.Contains(txs[0].Memo, "2333")) || (!strings.Contains(txs[1].Memo, "6666") && !strings.Contains(txs[1].Memo, "2333")) {
		println("zcash-cli" + " -datadir=" + cli.Conf + " z_listreceivedbyaddress " + cli.Vaddr)
		println("outstring:" + string(out))
		println("tx0:" + txs[0].Memo)
		println("tx1:" + txs[1].Memo)
		t.Fatal(errors.New("msg not match"))
	}
}

func aTestMarshall(t *testing.T) {
	out := `[{"txid":"d28128f07a39623681312c0e18d0acf0d900a3a061716b3597e99d4e5a5e8725", "amount": 1.00000000, "memo": "6666000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}]`
	var txs []ZTransaction
	err := json.Unmarshal([]byte(out), &txs)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%+v", txs)
}

func TestGetinfo(t *testing.T) {
	var err error
	miner := Setup("./miner")
	server := Setup("./server")
	client := Setup("./client")

	err = GetInfo(miner)
	if err != nil {
		t.Fatal(err)
	}

	err = GetInfo(server)
	if err != nil {
		t.Fatal(err)
	}

	err = GetInfo(client)
	if err != nil {
		t.Fatal(err)
	}

}

func TestMemo(t *testing.T) {
	var err error
	miner := Setup("./miner")
	server := Setup("./server")
	client := Setup("./client")

	//	Due to the implementation of mining process
	//	in ZCash, please bootstrap manually.
	//	Clean(miner)
	//	Clean(server)
	//	Clean(client)

	//	startHelper(t, miner)
	//	startHelper(t, server)
	//	startHelper(t, client)

	//	err = GenerateBlk(miner, "100")
	//	if err != nil {
	//		t.Fatal(err)
	//	}

	gettaddrHelper(t, miner)
	gettaddrHelper(t, server)
	gettaddrHelper(t, client)

	getzaddrHelper(t, miner)
	getzaddrHelper(t, server)
	getzaddrHelper(t, client)

	//	var out string
	sendmsgHelper(t, miner, server, client, "6666")
	// It takse some time to generate zkSNARK proof
	sleepHelper(t, "120")

	err = GenerateBlk(miner, "6")
	if err != nil {
		t.Fatal(err)
	}

	sendmsgHelper(t, miner, server, client, "2333")
	sleepHelper(t, "120")

	err = GenerateBlk(miner, "6")
	if err != nil {
		t.Fatal(err)
	}
	sleepHelper(t, "15")

	server.Vaddr = server.Zaddr
	checkHelper(t, server)

	var vkey string
	vkey, err = ExportViewingKey(server)
	if err != nil {
		t.Fatal(err)
	}

	err = ImportViewingKey(client, server.Zaddr, vkey)
	if err != nil {
		t.Fatal(err)
	}

	checkHelper(t, client)

	//	Stop(miner)
	//	Stop(server)
	//	Stop(client)
}
