package main

import (
	"context"
	"crypto/rand"
	"errors"
	"github.com/celestiaorg/celestia-node/api/rpc/client"
	"github.com/celestiaorg/celestia-node/api/rpc/perms"
	"github.com/celestiaorg/celestia-node/blob"
	"github.com/celestiaorg/celestia-node/libs/authtoken"
	"github.com/celestiaorg/celestia-node/libs/keystore"
	nodemod "github.com/celestiaorg/celestia-node/nodebuilder/node"
	"github.com/celestiaorg/celestia-node/share"
	"github.com/cristalhq/jwt"
	"github.com/filecoin-project/go-jsonrpc/auth"
	"github.com/mitchellh/go-homedir"
	"io"
	"log"
	"path/filepath"
)

func newKeystore(path string) (keystore.Keystore, error) {
	expanded, err := homedir.Expand(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return keystore.NewFSKeystore(filepath.Join(expanded, "keys"), nil)
}

func buildJWTToken(body []byte, permissions []auth.Permission) (string, error) {
	signer, err := jwt.NewHS256(body)
	if err != nil {
		return "", err
	}
	return authtoken.NewSignedJWT(signer, permissions)
}

func generateNewKey(ks keystore.Keystore) (keystore.PrivKey, error) {
	sk, err := io.ReadAll(io.LimitReader(rand.Reader, 32))
	if err != nil {
		return keystore.PrivKey{}, err
	}
	// save key
	key := keystore.PrivKey{Body: sk}
	err = ks.Put(nodemod.SecretName, key)
	if err != nil {
		return keystore.PrivKey{}, err
	}
	return key, nil
}

func main() {
	ks, err := newKeystore("~/.celestia-light-arabica-11")
	if err != nil {
		log.Println(err)
		return
	}

	key, err := ks.Get(nodemod.SecretName)
	if err != nil {
		if !errors.Is(err, keystore.ErrNotFound) {
			panic(err)
		}
		key, err = generateNewKey(ks)
		if err != nil {
			panic(err)
		}
	}

	token, err := buildJWTToken(key.Body, perms.ReadWritePerms)
	if err != nil {
		panic(err)
	}

	cli, err := client.NewClient(context.Background(), "http://localhost:26658", token)
	if err != nil {
		log.Println(err)
		panic(err)
	}

	msg := "Hello, Nico!"
	//blobs := []da.Blob{da.Blob(msg)}
	//
	//ns := namespace.MustNewV0([]byte("Aligned")).Bytes()
	//log.Println("namespace", hex.EncodeToString(ns))
	//ids, err := cli.DA.Submit(context.Background(), blobs, 0.1, ns)
	//if err != nil {
	//	log.Println(err)
	//	return
	//}

	ns, err := share.NewBlobNamespaceV0([]byte("Aligned"))
	if err != nil {
		panic(err)
	}

	b, err := blob.NewBlobV0(ns, []byte(msg))
	if err != nil {
		panic(err)
	}
	blobs := []*blob.Blob{b}
	height, err := cli.Blob.Submit(context.Background(), blobs, 0.1)
	if err != nil {
		log.Println(err)
		return
	}

	gotBlob, err := cli.Blob.Get(context.Background(), height, ns, b.Commitment)
	if err != nil {
		return
	}

	log.Println(string(gotBlob.Data))

	//log.Println(hex.EncodeToString(ids[0]))
	//
	//gotBlobs, err := cli.DA.Get(context.Background(), ids, ns)
	//if err != nil {
	//	return
	//}
	//
	//log.Println(hex.EncodeToString(gotBlobs[0]))

}
