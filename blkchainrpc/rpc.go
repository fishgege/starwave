package blkchainrpc

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type Zcash_cli struct {
	// Configure file of zcash client
	Conf string
	// Transparent address
	Taddr string
	// Shielded address
	Zaddr string
	// Shielded address with viewing key
	Vaddr string
	// Amount of ZCash remained in Taddr
	// Amount uint64

	TxConfirmTime string

	//	rpcuser string
	//	rpcpwd  string
}

// For Debug info
func (z *Zcash_cli) Print() {
	fmt.Println("Conf: " + z.Conf)
	fmt.Println("Taddr: " + z.Taddr)
	fmt.Println("Zaddr: " + z.Zaddr)
	fmt.Println("Vaddr: " + z.Vaddr)
	fmt.Println("TxConfirmTime: " + z.TxConfirmTime)
}

func (z *Zcash_cli) GetTaddr() string {
	return z.Taddr
}

func (z *Zcash_cli) GetZaddr() string {
	return z.Zaddr
}

func (z *Zcash_cli) GetVaddr() string {
	return z.Vaddr
}

func Setup(conf string) *Zcash_cli {
	cli := new(Zcash_cli)
	cli.Conf = conf
	//	cli.rpcuser = rpcuser
	//	cli.rpcpwd = rpcpwd

	return cli
}

func Start(cli *Zcash_cli) error {
	cmd := exec.Command("zcashd", "-datadir="+cli.Conf, "-daemon")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return err
	}

	return nil
}

func GetTAddr(cli *Zcash_cli) error {
	cmd := exec.Command("zcash-cli", "-datadir="+cli.Conf, "getnewaddress")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return err
	}

	cli.Taddr = out.String()

	return nil
}

func GetZAddr(cli *Zcash_cli) error {
	cmd := exec.Command("zcash-cli", "-datadir="+cli.Conf, "z_getnewaddress")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return err
	}

	cli.Zaddr = out.String()

	return nil
}

func GenerateBlk(cli *Zcash_cli, num string) error {
	cmd := exec.Command("zcash-cli", "-datadir="+cli.Conf, "generate", num)
	//	println("zcash-cli " + "-datadir=" + cli.Conf + " generate " + num)
	//var out bytes.Buffer
	//cmd.Stdout = &out
	//cmd := exec.Command("bash", "generate.sh")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return err
	}

	return nil
}

func SendToAddr(cli *Zcash_cli, addr string, num string) error {
	cmd := exec.Command("zcash-cli", "-datadir="+cli.Conf, "sendtoaddress", strings.TrimSpace(addr), num)
	//println("zcash-cli " + "-datadir=" + cli.Conf + " sendtoaddress " + strings.TrimSpace(addr) + " " + num)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return err
	}

	return nil
}

func GetInfo(cli *Zcash_cli) error {
	cmd := exec.Command("zcash-cli", "-datadir="+cli.Conf, "getinfo")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return err
	}

	return nil
}

// Due to the implementation of ZCash, fromaddr cannot be coinbase address currently.
func ZSendMany(cli *Zcash_cli, fromaddr string, toaddr string, amount string, memo string, leftamount string) (string, error) {
	cmd := exec.Command("zcash-cli", "-datadir="+cli.Conf, "z_sendmany", strings.TrimSpace(fromaddr),
		"[{\"address\": \""+strings.TrimSpace(toaddr)+"\", \"amount\": "+amount+", \"memo\": \""+memo+"\"},"+
			"{\"address\": \""+strings.TrimSpace(fromaddr)+"\", \"amount\": "+leftamount+"}]")
	//println("zcash-cli" + " -datadir=" + cli.Conf + " z_sendmany " + "\"" + strings.TrimSpace(fromaddr) + "\"" + " '[{\"address\": \"" + strings.TrimSpace(toaddr) + "\", \"amount\": " + amount + ", \"memo\": \"" + memo + "\"}," + "{\"address\": \"" + strings.TrimSpace(fromaddr) + "\", \"amount\": " + leftamount + "}]'")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return "", err
	}

	return out.String(), nil
}

func ZGetOperationStatus(cli *Zcash_cli, opid string) (string, error) {
	cmd := exec.Command("zcash-cli", "-datadir="+cli.Conf, "z_getoperationstatus", "[\""+strings.TrimSpace(opid)+"\"]")
	//println("zcash-cli" + " -datadir=" + cli.Conf + " z_getoperationstatus" + " '[\"" + strings.TrimSpace(opid) + "\"]'")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return "", err
	}

	return out.String(), nil
}

func ExportViewingKey(cli *Zcash_cli) (string, error) {
	if len(cli.Zaddr) <= 0 {
		return "", errors.New("z_exportviewingkey when zaddr is empty")
	}

	cmd := exec.Command("zcash-cli", "-datadir="+cli.Conf, "z_exportviewingkey", cli.Zaddr)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return "", err
	}

	return out.String(), nil
}

func ImportViewingKey(cli *Zcash_cli, addr string, vkey string) error {
	if len(cli.Vaddr) > 0 {
		return errors.New("z_importviewingkey when vaddr is not empty")
	}

	cmd := exec.Command("zcash-cli", "-datadir="+cli.Conf, "z_importviewingkey", vkey)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return err
	}

	cli.Vaddr = addr
	//	println(cli.Vaddr)
	return nil
}

func ListReceivedByVAddr(cli *Zcash_cli) (string, error) {
	if len(cli.Vaddr) <= 0 {
		return "", errors.New("z_listreceivedbyaddress when vaddr is empty")
	}

	cmd := exec.Command("zcash-cli", "-datadir="+cli.Conf, "z_listreceivedbyaddress", cli.Vaddr)
	//	println("zcash-cli" + " -datadir=" + cli.Conf + " z_listreceivedbyaddress " + cli.Vaddr)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return "", err
	}

	return out.String(), nil
}

func Stop(cli *Zcash_cli) error {
	cmd := exec.Command("zcash-cli", "-datadir="+cli.Conf, "stop")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return err
	}

	return nil
}

func Clean(cli *Zcash_cli) error {
	cmd := exec.Command("rm", "-rf", cli.Conf+"/regtest")
	//cmd := exec.Command("bash", "-c", `"rm -rf `+cli.Conf+"/regtest \"")
	//println("rm -rf " + cli.Conf + "/regtest")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return err
	}

	return nil
}

func ZValidatePaymentDisclosure(cli *Zcash_cli, proof string) error {
	cmd := exec.Command("zcash-cli", "-datadir="+cli.Conf, "z_validatepaymentdisclosure", proof)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}
