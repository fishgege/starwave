package blkchainrpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ucbrise/ghostor/blkchainrpc"
	"github.com/ucbrise/starwave/crypto/oaque"
	roaque "github.com/ucbrise/starwave/crypto/roaque/csroaque/optimized"
)

type OpStatus struct {
	Operationid    string
	Status         string
	execution_time string
	Result         ZTransaction
}

func SleepHelper(time string) error {
	cmd := exec.Command("sleep", time)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func GetTxID(out string) (string, error) {
	var ops []OpStatus

	err := json.Unmarshal([]byte(out), &ops)
	if err != nil {
		return "", err
	}

	return ops[0].Result.Txid, nil
}

func (cli *Zcash_cli) SendMemo(memo string) (string, error) {
	println("Start SendMemo")
	err := SendToAddr(cli, cli.GetTaddr(), "3")
	if err != nil {
		return "", err
	}
	SleepHelper("3")

	println("begin send memo")
	println(len(memo))
	opid, err := ZSendMany(cli, cli.GetTaddr(), cli.GetZaddr(), "1", memo, "1")
	if err != nil {
		return "", err
	}

	_, err = ZGetOperationStatus(cli, opid)
	if err != nil {
		return "", err
	}
	SleepHelper(cli.TxConfirmTime)

	println("get result")
	out, err := ZGetOperationStatus(cli, opid)
	if err != nil {
		return "", err
	}

	txid, err := GetTxID(out)
	if err != nil {
		return "", err
	}

	println(txid)
	// It takes about 2 mins to generate a zcash transaction due to zkSNARK.
	return txid, nil
}

const emptytxid = "0000000000000000000000000000000000000000000000000000000000000000"
const MemoLen = 512

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func (cli *Zcash_cli) SendMarshalledData(marshalled []byte) error {
	msgLen := MemoLen - len(emptytxid)
	idx := 0
	prev_id := emptytxid
	var err error
	println(len(marshalled))
	for idx < len(marshalled) {
		msg := string(marshalled[idx:min(len(marshalled), idx+msgLen)])
		tmp := strings.TrimSpace(prev_id) + strings.TrimSpace(msg)
		for len(tmp) < MemoLen {
			tmp = tmp + "0"
		}

		prev_id, err = cli.SendMemo(tmp)

		if err != nil {
			return err
		}
		idx = idx + msgLen
	}
	return nil
}

type RevocEntry struct {
	PrivateKeyList []*roaque.UnMarshalledKey
	Attrs          *oaque.AttributeList
}

type RevocationList []*RevocEntry

type MapEntry struct {
	prev_id string
	next    *MapEntry
	memo    string
}

func (cli *Zcash_cli) GenerateRevocList() (*RevocationList, error) {
	println("Start Generate RevocationList")
	out, err := ListReceivedByVAddr(cli)
	if err != nil {
		return nil, err
	}

	var txs []blkchainrpc.ZTransaction
	txs, err = blkchainrpc.GetZTransaction(out)
	if err != nil {
		return nil, err
	}

	fmt.Printf("The number of Txs: %d\n", len(txs))

	txMap := make(map[string]*MapEntry)
	for i := 0; i < len(txs); i++ {
		tmp := &MapEntry{next: nil, memo: txs[i].Memo[len(emptytxid):]}
		tmp.prev_id = txs[i].Memo[0:len(emptytxid)]
		txMap[txs[i].Txid] = tmp
	}

	for _, entry := range txMap {
		if entry.prev_id != emptytxid {
			//println(entry.prev_id)
			txMap[entry.prev_id].next = entry
		}
	}

	revoc := make(RevocationList, 0)
	for i := 0; i < len(txs); i++ {
		if txs[i].Memo[0:len(emptytxid)] == emptytxid {
			res := make([]byte, 0)
			entry := txMap[txs[i].Txid]
			for entry != nil {
				res = append(res, []byte(entry.memo)...)
				entry = entry.next
			}

			tmp := &RevocEntry{}
			tmp.PrivateKeyList, tmp.Attrs, err = roaque.UnMarshalKey(res)
			if err != nil {
				return nil, err
			}

			revoc = append(revoc, tmp)
		}
	}
	return &revoc, nil
}
