package swbind

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/SoftwareDefinedBuildings/starwave/starwave"
	"github.com/immesys/bw2/objects"
	"github.com/immesys/bw2bind"
)

type SWClient struct {
	*bw2bind.BW2Client
	myhash   string
	mysecret *starwave.EntitySecret
	nskey    *starwave.DecryptionKey
}

/* Some important utilities */

func StartOfTime() time.Time {
	t, err := time.Parse(time.RFC822Z, "01 Jan 15 00:00 +0000")
	if err != nil {
		panic(err)
	}
	return t
}

func Connect(to string) (*SWClient, error) {
	bw2c, err := bw2bind.Connect(to)
	if err != nil {
		return nil, err
	}
	c := new(SWClient)
	c.BW2Client = bw2c
	return c, err
}

func ConnectOrExit(to string) *SWClient {
	return &SWClient{
		BW2Client: bw2bind.ConnectOrExit(to),
	}
}

func extractNamespace(uri string) (string, string) {
	res := strings.SplitN(uri, "/", 2)
	return res[0], res[1]
}

func getEntity(swc *SWClient, vk string) (*objects.Entity, error) {
	ro, _, err := swc.ResolveRegistry(vk)
	if err != nil {
		return nil, err
	}
	entity := ro.(*objects.Entity)
	return entity, nil
}

func resolveChain(swc *SWClient, chain *bw2bind.SimpleChain) ([]*starwave.DelegationBundle, error) {
	ro, _, err := swc.ResolveRegistry(chain.Hash)
	if err != nil {
		return nil, err
	}
	fullchain := ro.(*objects.DChain)
	bundles := make([]*starwave.DelegationBundle, fullchain.NumHashes())
	for i := range bundles {
		dot := fullchain.GetDOT(i)
		bundles[i] = new(starwave.DelegationBundle)
		success := bundles[i].Unmarshal([]byte(dot.GetComment()))
		if !success {
			return nil, fmt.Errorf("Invalid DelegationBundle at index %d of DoT Chain", i)
		}
	}
	return bundles, nil
}

/*
 * Setting the local entity. Unfortunately, there are many methods I need to
 * override, although I am not actually adding that much functionality.
 */

func (swc *SWClient) setLocalSecrets(input []byte) []byte {
	input, swc.mysecret, swc.nskey = extractSecretsFromEntity(input, true)
	if swc.mysecret == nil || swc.nskey == nil {
		panic("Setting local entity to non-STARWAVE entity")
	}
	return input
}

func (swc *SWClient) SetEntity(keyfile []byte) (vk string, err error) {
	keyfile = swc.setLocalSecrets(keyfile)
	if keyfile == nil {
		return "", errors.New("Entity has invalid STARWAVE secrets")
	}
	vk, err = swc.BW2Client.SetEntity(keyfile)
	if err != nil {
		swc.myhash = vk
	}
	return
}

func (swc *SWClient) SetEntityFile(filename string) (vk string, err error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return swc.SetEntity(contents[1:])
}

func (swc *SWClient) SetEntityFileOrExit(filename string) (vk string) {
	rv, e := swc.SetEntityFile(filename)
	if e != nil {
		fmt.Fprintln(os.Stderr, "Could not set entity file:", e.Error())
		os.Exit(1)
	}
	return rv
}

func (swc *SWClient) SetEntityFromEnvironOrExit() (vk string) {
	fname := os.Getenv("BW2_DEFAULT_ENTITY")
	if fname == "" {
		fmt.Fprintln(os.Stderr, "$BW2_DEFAULT_ENTITY not set")
		os.Exit(1)
	}
	return swc.SetEntityFileOrExit(fname)
}

func (swc *SWClient) SetEntityOrExit(keyfile []byte) (vk string) {
	rv, e := swc.SetEntity(keyfile)
	if e != nil {
		fmt.Fprintln(os.Stderr, "Could not set entity :", e.Error())
		os.Exit(1)
	}
	return rv
}

/* Creating DOTs. I need to modify these so they delegate OAQUE keys too. */

func (swc *SWClient) CreateDOT(p *bw2bind.CreateDOTParams) (string, []byte, error) {
	// Only subscribe DoTs change
	if !strings.Contains(p.AccessPermissions, "C") {
		return swc.BW2Client.CreateDOT(p)
	}

	// Don't support ExpiryDelta
	var expiry time.Time
	if p.Expiry == nil {
		var delta time.Duration
		if p.ExpiryDelta == nil {
			// Default is 30 days
			delta = 30 * 24 * time.Hour
		} else {
			delta = *p.ExpiryDelta
		}
		expiry = time.Now().Add(delta)
	} else {
		expiry = *p.Expiry
	}
	p.ExpiryDelta = nil

	namespace, uri := extractNamespace(p.URI)
	perms, err := starwave.PermissionRange(uri, StartOfTime(), expiry)
	if err != nil {
		return "", nil, err
	}

	// Now I need to figure out what keys I can include in the DoT
	var keys []*starwave.DecryptionKey
	if namespace == swc.myhash {
		// Just include the master key. DelegateBundle() should deal with
		// generating the appropriate subkeys.
		keys = []*starwave.DecryptionKey{swc.nskey}
	} else {
		keys = make([]*starwave.DecryptionKey, len(perms))
		chains, err := swc.BuildChain(p.URI, "C", swc.myhash)
		for chain := range chains {
			bundles, err := resolveChain(swc, chain)
			if err != nil {
				// Don't let one bad chain make the whole thing unusable
				continue
			}
			for i, perm := range perms {
				if keys[i] != nil {
					keys[i] = starwave.DeriveKey(bundles, perm, swc.mysecret)
				}
			}
			// TODO: Also include partially overlapping keys
		}
		if err != nil {
			return "", nil, err
		}
	}

	// Filter out nil keys
	filteredkeys := keys[:0]
	for _, key := range keys {
		if key != nil {
			filteredkeys = append(filteredkeys, key)
		}
	}

	// Get Hierarchy params
	authority, err := getEntity(swc, namespace)
	if err != nil {
		return "", nil, err
	}
	hd := new(starwave.HierarchyDescriptor)
	success := hd.Unmarshal([]byte(authority.GetContact()))
	if !success {
		return "", nil, errors.New("Invalid hierarchy descriptor in namespace authority")
	}

	// Get params of destination
	to, err := getEntity(swc, p.To)
	if err != nil {
		return "", nil, err
	}
	ed := new(starwave.EntityDescriptor)
	success = ed.Unmarshal([]byte(to.GetComment()))
	if !success {
		return "", nil, errors.New("Invalid entity descriptor in destination entity")
	}

	// Perform the delegation
	db, err := starwave.DelegateBundle(rand.Reader, hd, swc.mysecret, filteredkeys, ed, uri, StartOfTime(), expiry)
	if err != nil {
		return "", nil, err
	}
	p.Comment = string(db.Marshal())

	return swc.BW2Client.CreateDOT(p)
}

/* Publishing messages. Need to make sure that POs are encrypted. */

func encryptPO(random io.Reader, hd *starwave.HierarchyDescriptor, perm *starwave.Permission, po bw2bind.PayloadObject) (bw2bind.PayloadObject, error) {
	contents := po.GetContents()
	buf := make([]byte, 4+len(contents))
	binary.LittleEndian.PutUint32(buf[:4], uint32(po.GetPONum()))
	copy(buf[4:], contents)

	message, err := starwave.Encrypt(random, hd, perm, buf)
	if err != nil {
		return nil, err
	}

	encrypted := new(bw2bind.PayloadObjectImpl)
	encrypted.SetPONum(bw2bind.PONumPOEncryptedSTARWAVE)
	encrypted.SetContents(message.Marshal())
	return encrypted, nil
}

func decryptPO(d *starwave.Decryptor, po bw2bind.PayloadObject) bw2bind.PayloadObject {
	if po.GetPONum() != bw2bind.PONumPOEncryptedSTARWAVE {
		panic("Trying to decrypt message which is not STARWAVE-encrypted")
	}
	message := new(starwave.EncryptedMessage)
	success := message.Unmarshal(po.GetContents())
	if !success {
		return nil
	}
	buf := d.Decrypt(message)
	if buf == nil {
		return nil
	}

	ponum := binary.LittleEndian.Uint32(buf[:4])
	contents := buf[4:]
	decrypted := new(bw2bind.PayloadObjectImpl)
	decrypted.SetPONum(int(ponum))
	decrypted.SetContents(contents)
	return decrypted
}

func (swc *SWClient) Publish(p *bw2bind.PublishParams) error {
	namespace, uri := extractNamespace(p.URI)
	perm, err := starwave.ParsePermission(uri, time.Now())
	if err != nil {
		return err
	}

	// Get Hierarchy params
	authority, err := getEntity(swc, namespace)
	if err != nil {
		return err
	}
	hd := new(starwave.HierarchyDescriptor)
	success := hd.Unmarshal([]byte(authority.GetContact()))
	if !success {
		return errors.New("Invalid hierarchy descriptor in namespace authority")
	}

	for i, po := range p.PayloadObjects {
		p.PayloadObjects[i], err = encryptPO(rand.Reader, hd, perm, po)
		if err != nil {
			return err
		}
	}

	// Encrypt each payload object
	return swc.BW2Client.Publish(p)
}

/* Building chains. When subscribing, we need to be able to obtain keys. */

func (swc *SWClient) obtainKey(namespace string, perm *starwave.Permission) (*starwave.DecryptionKey, error) {
	fullURI := strings.Join([]string{namespace, perm.URI.String()}, "/")

	var key *starwave.DecryptionKey
	chains, err := swc.BW2Client.BuildChain(fullURI, "C", swc.myhash)
	for chain := range chains {
		bundles, err := resolveChain(swc, chain)
		if err != nil {
			// Don't let one bad chain make the whole thing unusable
			continue
		}
		key = starwave.DeriveKey(bundles, perm, swc.mysecret)
		if key != nil {
			break
		}
	}
	if err != nil && key == nil {
		return nil, err
	}

	return key, nil
}

func (swc *SWClient) subscribeDecryptor(input <-chan *bw2bind.SimpleMessage) chan *bw2bind.SimpleMessage {
	output := make(chan *bw2bind.SimpleMessage, 1024)
	go func() {
		var decryptor *starwave.Decryptor
		var cachedperm *starwave.Permission
		for msg := range input {
			namespace := strings.SplitN(msg.URI, "/", 2)[0]
			for i, po := range msg.POs {
				if po.GetPONum() == bw2bind.PONumPOEncryptedSTARWAVE {
					emsg := new(starwave.EncryptedMessage)
					emsg.Unmarshal(po.GetContents())
					perm := emsg.Key.Permissions
					if cachedperm == nil || !perm.Equals(cachedperm) {
						// Need to get a decryptor
						key, err := swc.obtainKey(namespace, perm)
						if err != nil || key == nil {
							continue
						}
						decryptor = starwave.PrepareDecryption(perm, key)
					}
					if decryptor != nil && perm.Equals(cachedperm) {
						// Decrypt the PO
						msg.POs[i] = decryptPO(decryptor, po)
					}
				}
			}
			output <- msg
		}
		close(output)
	}()
	return output
}

func (swc *SWClient) Subscribe(p *bw2bind.SubscribeParams) (chan *bw2bind.SimpleMessage, error) {
	messages, err := swc.BW2Client.Subscribe(p)
	if err != nil {
		return nil, err
	}
	return swc.subscribeDecryptor(messages), nil
}

func (swc *SWClient) SubscribeH(p *bw2bind.SubscribeParams) (chan *bw2bind.SimpleMessage, string, error) {
	messages, handle, err := swc.BW2Client.SubscribeH(p)
	if err != nil {
		return nil, handle, err
	}
	return swc.subscribeDecryptor(messages), handle, nil
}

func (swc *SWClient) SubscribeOrExit(p *bw2bind.SubscribeParams) chan *bw2bind.SimpleMessage {
	messages := swc.BW2Client.SubscribeOrExit(p)
	return swc.subscribeDecryptor(messages)
}

func (swc *SWClient) Query(p *bw2bind.QueryParams) (chan *bw2bind.SimpleMessage, error) {
	messages, err := swc.BW2Client.Query(p)
	if err != nil {
		return nil, err
	}
	return swc.subscribeDecryptor(messages), nil
}

func (swc *SWClient) QueryOne(p *bw2bind.QueryParams) (*bw2bind.SimpleMessage, error) {
	message, err := swc.BW2Client.QueryOne(p)
	if err != nil {
		return nil, err
	}
	input := make(chan *bw2bind.SimpleMessage, 1)
	input <- message
	output := swc.subscribeDecryptor(input)
	close(input)
	message = <-output
	return message, err
}

func (swc *SWClient) QueryOneOrExit(p *bw2bind.QueryParams) *bw2bind.SimpleMessage {
	rv, err := swc.QueryOne(p)
	if err != nil {
		fmt.Printf("Could not query: %v\n", err)
		os.Exit(1)
	}
	return rv
}

func (swc *SWClient) QueryOrExit(p *bw2bind.QueryParams) chan *bw2bind.SimpleMessage {
	messages := swc.BW2Client.QueryOrExit(p)
	return swc.subscribeDecryptor(messages)
}

// Creation of entities.

// This suffix indicates that an entity contains STARWAVE secrets.
var magicEntitySuffix = []byte{180, 247, 117, 78, 239, 80, 110, 253, 171, 214, 166, 250, 180, 104, 213, 50, 119, 29, 188, 138, 159, 229, 153, 145, 241, 194, 111, 91, 220, 70, 146, 169, 55, 209, 134, 24, 166, 182, 184, 168, 235, 86, 237, 56, 185, 210, 88, 164, 81, 252, 255, 92, 173, 85, 250, 109, 90, 2, 242, 82, 92, 249, 156, 189}

func appendSecretsToEntity(entity []byte, es *starwave.EntitySecret, master *starwave.DecryptionKey) []byte {
	esm := es.Marshal()
	masterm := master.Marshal()
	lenbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenbuf, uint32(len(esm)))
	entity = append(entity, lenbuf...)
	entity = append(entity, esm...)
	entity = append(entity, masterm...)

	binary.LittleEndian.PutUint32(lenbuf, uint32(len(lenbuf)+len(esm)+len(masterm)))
	entity = append(entity, lenbuf...)
	entity = append(entity, magicEntitySuffix...)
	return entity
}

// Returns the original entity if it didn't have STARWAVE secrets appended
func extractSecretsFromEntity(entity []byte, unmarshalSecrets bool) ([]byte, *starwave.EntitySecret, *starwave.DecryptionKey) {
	last64bytes := entity[len(entity)-len(magicEntitySuffix):]
	if bytes.Equal(last64bytes, magicEntitySuffix) {
		// This is a STARWAVE entity with appended secrets
		entity = entity[:len(entity)-len(magicEntitySuffix)]
		footerlen := binary.LittleEndian.Uint32(entity[len(entity)-4:])
		entity = entity[:len(entity)-4]
		footerstartidx := len(entity) - int(footerlen)
		footer := entity[footerstartidx:]
		entity = entity[:footerstartidx]
		if !unmarshalSecrets {
			return entity, nil, nil
		}

		esmlen := binary.LittleEndian.Uint32(footer[:4])
		footer = footer[4:]
		esm := footer[:esmlen]
		masterm := footer[esmlen:]

		es := new(starwave.EntitySecret)
		success := es.Unmarshal(esm)
		if !success {
			fmt.Println("Could not unmarshal entity secret")
			return entity, nil, nil
		}
		master := new(starwave.DecryptionKey)
		success = master.Unmarshal(masterm)
		if !success {
			fmt.Println("Could not unmarshal hierarhcy secret")
			return entity, es, nil
		}

		return entity, es, master
	} else {
		// This is a regular BOSSWAVE entity.
		return entity, nil, nil
	}
}

func (swc *SWClient) CreateEntity(p *bw2bind.CreateEntityParams) (string, []byte, error) {
	vk, binrep, err := swc.BW2Client.CreateEntity(p)
	if err != nil {
		return "", nil, err
	}

	ed, es, err := starwave.CreateEntity(rand.Reader, p.Contact)
	if err != nil {
		return "", nil, err
	}
	hd, master, err := starwave.CreateHierarchy(rand.Reader, p.Comment)
	if err != nil {
		return "", nil, err
	}
	p.Contact = string(ed.Marshal())
	p.Comment = string(hd.Marshal())

	return vk, appendSecretsToEntity(binrep, es, master), err
}

func (swc *SWClient) PublishEntityWithAcc(blob []byte, account int) (string, error) {
	blob, _, _ = extractSecretsFromEntity(blob, false)
	return swc.BW2Client.PublishEntityWithAcc(blob, account)
}

func (swc *SWClient) PublishEntity(blob []byte) (string, error) {
	return swc.PublishEntityWithAcc(blob, 0)
}

/* Other functions */

func SilenceLog() {
	bw2bind.SilenceLog()
}
