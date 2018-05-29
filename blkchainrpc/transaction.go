package blkchainrpc

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
)

type ZTransaction struct {
	Txid   string
	Amount float64
	Memo   string
}

func GetZTransaction(out string) ([]ZTransaction, error) {
	var txs []ZTransaction

	err := json.Unmarshal([]byte(out), &txs)
	if err != nil {
		return nil, err
	}

	return txs, nil
}

func GenerateMemo(epoch uint64, hash []byte, signature []byte) string {
	epochString := strconv.FormatUint(epoch, 10)

	str := make([]byte, 0, len(hash)+len(signature)+1+len(epochString))
	str = append(str, hash...)
	str = append(str, signature...)
	str = append(str, []byte(epochString+"$")...)
	return hex.EncodeToString(str)
}
