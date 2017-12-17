package swbind

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/immesys/bw2/objects"
	"github.com/immesys/bw2bind"
	"github.com/ucbrise/starwave/starwave"
)

type SWClient struct {
	*bw2bind.BW2Client
	myvk     string
	myself   *objects.Entity
	mysecret *starwave.EntitySecret
	nskey    *starwave.DecryptionKey
}

func (swc *SWClient) GetEntity() *objects.Entity {
	return swc.myself
}

var dotnonce = []byte{0xae, 0x30, 0x35, 0xd7, 0xcc, 0xdb, 0xe1, 0xae}

/* Some important utilities */

func StartOfTime() time.Time {
	t, err := time.Parse(time.RFC822Z, "01 Jan 17 00:00 +0000")
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

func resolveChain(swc *SWClient, chain *bw2bind.SimpleChain, perm *starwave.Permission) ([]*starwave.DelegationBundle, error) {
	numdots := len(chain.Content) >> 5
	bundles := make([]*starwave.DelegationBundle, numdots)
	for i := range bundles {
		dothash := chain.Content[i<<5 : (i<<5)+32]
		ro, _, err := swc.ResolveRegistry(base64.URLEncoding.EncodeToString(dothash))
		if err != nil {
			return nil, err
		}
		dot := ro.(*objects.DOT)
		dotcontent := dot.GetContent()
		dotdata := GetCommentInDOT(dotcontent)
		if len(dotdata) == 0 {
			return nil, err
		}
		// Each DelegationBundle will contain the single FullDelegation with
		// permissions that could possibly match.
		if len(dotdata) < 24 || !bytes.Equal(dotdata[0:8], dotnonce) {
			return nil, fmt.Errorf("Invalid DelegationBundle at index %d of DoT Chain", i)
		}

		starttime := time.Unix(0, int64(binary.LittleEndian.Uint64(dotdata[8:16])))
		endtime := time.Unix(0, int64(binary.LittleEndian.Uint64(dotdata[16:24])))
		perms, err := starwave.PermissionRange(perm.URI.String(), starttime, endtime)
		if err != nil {
			panic(err)
		}

		correctIndex := -1
		for j, entperm := range perms {
			if entperm.Contains(perm) {
				correctIndex = j
				break
			}
		}
		if correctIndex == -1 {
			// This DoT isn't useful
			return nil, fmt.Errorf("DoT at index %d didn't contain a delegation with the necessary permissions", i)
		}

		enthashidx := 24 + (correctIndex << 5)
		enthash := dotdata[enthashidx : enthashidx+32]

		ro, _, err = swc.ResolveRegistry(base64.URLEncoding.EncodeToString(enthash))
		if err != nil {
			return nil, err
		}
		ent := ro.(*objects.Entity)

		bundles[i] = new(starwave.DelegationBundle)
		bundles[i].Delegations = []*starwave.FullDelegation{new(starwave.FullDelegation)}
		success := bundles[i].Delegations[0].Unmarshal(GetCommentInEntity(ent.GetContent()))
		if !success {
			return nil, fmt.Errorf("Invalid DelegationBundle at index %d of DoT Chain", i)
		}

		hdhash := base64.URLEncoding.EncodeToString(dot.GetAccessURIMVK())
		giverhash := base64.URLEncoding.EncodeToString(dot.GetGiverVK())
		receiverhash := base64.URLEncoding.EncodeToString(dot.GetReceiverVK())

		nsauth, _, err := swc.ResolveRegistry(hdhash)
		if err != nil {
			return nil, err
		}
		giver, _, err := swc.ResolveRegistry(giverhash)
		if err != nil {
			return nil, err
		}
		receiver, _, err := swc.ResolveRegistry(receiverhash)
		if err != nil {
			return nil, err
		}

		hd := new(starwave.HierarchyDescriptor)
		hd.Unmarshal(GetCommentInEntity(nsauth.GetContent()))
		to := new(starwave.EntityDescriptor)
		to.Unmarshal(GetContactInEntity(giver.GetContent()))
		from := new(starwave.EntityDescriptor)
		from.Unmarshal(GetContactInEntity(receiver.GetContent()))

		bundles[i].Decompress(from, to, hd)
	}

	return bundles, nil
}

/*
 * Setting the local entity. Unfortunately, there are many methods I need to
 * override, although I am not actually adding that much functionality.
 */

func (swc *SWClient) setLocalSecrets(input []byte) []byte {
	input, swc.mysecret, swc.nskey = extractSecretsFromEntity(input, true, true)
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
	if err == nil {
		robj, err := objects.NewEntity(objects.ROEntityWKey, keyfile)
		if err != nil {
			panic("Able to set entity to invalid keyfile")
		}
		e := robj.(*objects.Entity)
		swc.myself = e
		swc.myvk = e.StringKey()

		if swc.myvk != vk {
			panic("Parsed VK is not equal to the returned VK")
		}
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
	if namespace == swc.myvk {
		// Just include the master key. DelegateBundle() should deal with
		// generating the appropriate subkeys.
		keys = []*starwave.DecryptionKey{swc.nskey}
	} else {
		keys = make([]*starwave.DecryptionKey, len(perms))
		for i, perm := range perms {
			key, err := swc.ObtainKey(namespace, perm)
			if err == nil {
				keys[i] = key
			}
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
	authority, _, err := swc.ResolveRegistry(namespace)
	if err != nil {
		return "", nil, err
	}

	hd := new(starwave.HierarchyDescriptor)
	success := hd.Unmarshal(GetCommentInEntity(authority.GetContent()))
	if !success {
		return "", nil, errors.New("Invalid hierarchy descriptor in namespace authority")
	}

	// Get params of destination
	to, _, err := swc.ResolveRegistry(p.To)
	if err != nil {
		return "", nil, err
	}
	ed := new(starwave.EntityDescriptor)
	success = ed.Unmarshal(GetContactInEntity(to.GetContent()))
	if !success {
		return "", nil, errors.New("Invalid entity descriptor in destination entity")
	}

	// Perform the delegation
	db, err := starwave.DelegateBundle(rand.Reader, hd, swc.mysecret, filteredkeys, ed, uri, StartOfTime(), expiry)
	if err != nil {
		return "", nil, err
	}

	db.Compress()

	dotdata := make([]byte, 24, 16+(len(db.Delegations)<<5))

	copy(dotdata[0:8], dotnonce)
	binary.LittleEndian.PutUint64(dotdata[8:16], uint64(StartOfTime().UnixNano()))
	binary.LittleEndian.PutUint64(dotdata[16:24], uint64(expiry.UnixNano()))
	entities := make([][]byte, len(db.Delegations))
	for i, deleg := range db.Delegations {
		comment := deleg.Marshal()
		entity := objects.CreateNewEntity("", "", nil)
		vk := entity.GetVK()
		dotdata = append(dotdata, vk...)

		content := entity.GetContent()
		content = AddContactAndCommentToEntity(content, []byte{}, comment, entity.GetSK())
		entities[i] = content
	}

	p.Comment = ""

	hash, dotcontent, err := swc.BW2Client.CreateDOT(p)
	if err != nil {
		return "", nil, err
	}

	dotcontent = AddContactAndCommentToDOT(dotcontent, []byte{}, dotdata, swc.myself.GetSK())
	hash = base64.URLEncoding.EncodeToString(GetDOTHash(dotdata))

	// OK, so I need to get the content, and then append all of the entities on
	// to the end of it.

	// Add the length of each entity, followed by the entity.
	for _, entcontent := range entities {
		entlength := len(entcontent)

		lenbuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenbuf, uint32(entlength))
		dotcontent = append(dotcontent, lenbuf...)
		dotcontent = append(dotcontent, entcontent...)
	}

	return hash, dotcontent, nil
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
	authority, _, err := swc.ResolveRegistry(namespace)
	if err != nil {
		return err
	}
	hd := new(starwave.HierarchyDescriptor)
	success := hd.Unmarshal(GetCommentInEntity(authority.GetContent()))
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

func (swc *SWClient) ObtainKey(namespace string, perm *starwave.Permission) (*starwave.DecryptionKey, error) {
	fullURI := strings.Join([]string{namespace, perm.URI.String()}, "/")

	var key *starwave.DecryptionKey
	chains, err := swc.BW2Client.BuildChain(fullURI, "C", swc.myvk)
	for chain := range chains {
		bundles, err := resolveChain(swc, chain, perm)
		if bundles == nil || err != nil {
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
						key, err := swc.ObtainKey(namespace, perm)
						if err != nil || key == nil {
							fmt.Println("Could not obtain decryptor")
							continue
						}
						decryptor = starwave.PrepareDecryption(perm, key)
						cachedperm = perm
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

func appendSecretsToEntity(entity []byte, es *starwave.EntitySecret, master *starwave.DecryptionKey) []byte {
	esm := es.Marshal()
	masterm := master.Marshal()
	lenbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenbuf, uint32(len(esm)))
	entity = append(entity, lenbuf...)
	entity = append(entity, esm...)
	entity = append(entity, masterm...)

	return entity
}

// Returns the original entity if it didn't have STARWAVE secrets appended
func extractSecretsFromEntity(entity []byte, containsSK bool, unmarshalSecrets bool) ([]byte, *starwave.EntitySecret, *starwave.DecryptionKey) {
	var endidx int
	if containsSK {
		endidx = EndOfEntityWithKey(entity)
	} else {
		endidx = EndOfEntity(entity)
	}

	if endidx == len(entity) {
		// This is a regular BOSSWAVE entity.
		return entity, nil, nil
	}

	if !unmarshalSecrets {
		return entity[:endidx], nil, nil
	}

	// This is a STARWAVE entity, with additional secrets in the footer

	footer := entity[endidx:]
	entity = entity[:endidx]

	esmlen := binary.LittleEndian.Uint32(footer[:4])
	footer = footer[4:]
	esm := footer[:esmlen]
	masterm := footer[esmlen:]

	es := new(starwave.EntitySecret)
	success := es.Unmarshal(esm)
	if !success {
		return entity, nil, nil
	}
	master := new(starwave.DecryptionKey)
	success = master.Unmarshal(masterm)
	if !success {
		return entity, es, nil
	}

	return entity, es, master
}

func (swc *SWClient) CreateEntity(p *bw2bind.CreateEntityParams) (string, []byte, error) {
	ed, es, err := starwave.CreateEntity(rand.Reader, p.Contact)
	if err != nil {
		return "", nil, err
	}
	hd, master, err := starwave.CreateHierarchy(rand.Reader, p.Comment)
	if err != nil {
		return "", nil, err
	}

	p.Contact = ""
	p.Comment = ""

	vk, binrep, err := swc.BW2Client.CreateEntity(p)
	if err != nil {
		return "", nil, err
	}

	binrep = AddContactAndCommentToEntityWithKey(binrep, ed.Marshal(), hd.Marshal())

	return vk, appendSecretsToEntity(binrep, es, master), nil
}

func (swc *SWClient) PublishEntityWithAcc(blob []byte, account int) (string, error) {
	blob, _, _ = extractSecretsFromEntity(blob, false, false)
	return swc.BW2Client.PublishEntityWithAcc(blob, account)
}

func (swc *SWClient) PublishEntity(blob []byte) (string, error) {
	return swc.PublishEntityWithAcc(blob, 0)
}

func (swc *SWClient) PublishDOTWithAcc(blob []byte, account int) (string, error) {
	// We need to publish the actual DoT, as well as any key-containing entities
	// we may have appended to it

	index := EndOfDOT(blob)

	// Now we at the end of the DoT
	dot := blob[:index]
	entities := blob[index:]

	var aerr atomic.Value

	wg := &sync.WaitGroup{}
	// Publish each entity in a goroutine
	for len(entities) != 0 {
		entitylen := binary.LittleEndian.Uint32(entities[0:4])
		entity := entities[4 : 4+entitylen]
		entities = entities[4+entitylen:]

		// Publish each entity at the end of the DOT
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, err := swc.BW2Client.PublishEntityWithAcc(entity, account)
			if err != nil {
				aerr.Store(err)
			}
		}()
	}

	// Finally, publish the actual DoT
	hash, err := swc.BW2Client.PublishDOTWithAcc(dot, account)

	// Wait for all publishing to complete
	wg.Wait()

	if terr := aerr.Load(); terr != nil {
		return hash, terr.(error)
	}
	return hash, err
}

func (swc *SWClient) PublishDOT(blob []byte) (string, error) {
	return swc.PublishDOTWithAcc(blob, 0)
}
