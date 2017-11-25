package swbind

import (
	"crypto/rand"
	"errors"
	"fmt"
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
}

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

func (swc *SWClient) CreateDOT(p *bw2bind.CreateDOTParams) (string, []byte, error) {
	// Only subscribe DoTs change
	if !strings.Contains(p.AccessPermissions, "S") {
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
	keys := make([]*starwave.DecryptionKey, len(perms))
	chains, err := swc.BuildChain(p.URI, "S", swc.myhash)
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
