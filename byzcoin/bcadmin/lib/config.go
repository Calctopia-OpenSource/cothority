package lib

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

// ConfigPath points to where the files will be stored by default.
var ConfigPath = "."

// This var is used to check if an identity is empty. It helps providing some
// insights to users in special cases, for example when using "bcadmin link"
// that ends up using an empty identity if none is provided.
var emptyID = make([]byte, 32)

// BcaName is used for cliApp.Name and the default config folder of bcadmin.
const BcaName = "bcadmin"

// Config is the structure used by ol to save its configuration. It holds
// everything necessary to talk to a ByzCoin instance. The AdminDarc and
// AdminIdentity can change over the lifetime of a ledger.
type Config struct {
	Roster        onet.Roster
	ByzCoinID     skipchain.SkipBlockID
	AdminDarc     darc.Darc
	AdminIdentity darc.Identity
}

func (c Config) String() string {
	out := new(strings.Builder)
	out.WriteString("- Config:\n")
	out.WriteString("-- Roster:\n")
	for _, serverIdentity := range c.Roster.List {
		fmt.Fprintf(out, "--- %s\n", serverIdentity.String())
	}
	fmt.Fprintf(out, "-- ByzCoinID: %x\n", c.ByzCoinID)
	fmt.Fprintf(out, "-- AdminDarc: %x\n", c.AdminDarc.GetBaseID())
	fmt.Fprintf(out, "-- Identity: %s", c.AdminIdentity.String())
	return out.String()
}

// LoadKey returns the signer of a given identity. It searches it in the
// ConfigPath. If the identity is empty it return an error.
func LoadKey(id darc.Identity) (*darc.Signer, error) {
	// Check if this is an empty identity. Note: we expect an identity to use 32
	// bytes
	if bytes.Equal(id.GetPublicBytes(), emptyID) {
		return nil, errors.New("failed to load the key because the identity is empty")
	}
	// Find private key file.
	fn := fmt.Sprintf("key-%s.cfg", id)
	fn = filepath.Join(ConfigPath, fn)
	return LoadSigner(fn)
}

// LoadKeyFromString returns a signer based on a string representing the public
// identity of the signer
func LoadKeyFromString(id string) (*darc.Signer, error) {
	// Find private key file.
	fn := fmt.Sprintf("key-%s.cfg", id)
	fn = filepath.Join(ConfigPath, fn)
	return LoadSigner(fn)
}

// LoadSigner loads a signer from a file given by fn.
func LoadSigner(fn string) (*darc.Signer, error) {
	buf, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("failed to read this path: '%s': %v", fn, err)
	}

	var signer darc.Signer
	err = protobuf.DecodeWithConstructors(buf, &signer,
		network.DefaultConstructors(cothority.Suite))
	if err != nil {
		return nil, err
	}

	return &signer, err
}

// SaveKey stores a signer in a file.
func SaveKey(signer darc.Signer) error {
	os.MkdirAll(ConfigPath, 0755)

	fn := fmt.Sprintf("key-%s.cfg", signer.Identity())
	fn = filepath.Join(ConfigPath, fn)

	// perms = 0400 because there is key material inside this file.
	f, err := os.OpenFile(fn, os.O_RDWR|os.O_CREATE, 0400)
	if err != nil {
		return fmt.Errorf("could not write %v: %v", fn, err)
	}

	buf, err := protobuf.Encode(&signer)
	if err != nil {
		return err
	}
	_, err = f.Write(buf)
	if err != nil {
		return err
	}
	return f.Close()
}

// SaveConfig stores the config in the ConfigPath directory. It returns the
// pathname of the stored file.
func SaveConfig(cfg Config) (string, error) {
	os.MkdirAll(ConfigPath, 0755)

	fn := fmt.Sprintf("bc-%x.cfg", cfg.ByzCoinID)
	fn = filepath.Join(ConfigPath, fn)

	buf, err := protobuf.Encode(&cfg)
	if err != nil {
		return fn, err
	}
	err = ioutil.WriteFile(fn, buf, 0644)
	if err != nil {
		return fn, err
	}

	return fn, nil
}

// SafeSaveConfig does the same as SaveConfig but it checks if the file already
// exist and returns an error if this is the case.
func SafeSaveConfig(cfg Config) (string, error) {
	os.MkdirAll(ConfigPath, 0755)

	fn := fmt.Sprintf("bc-%x.cfg", cfg.ByzCoinID)
	fn = filepath.Join(ConfigPath, fn)
	_, err := os.Stat(fn)
	if os.IsNotExist(err) {
		return SaveConfig((cfg))
	}
	if err != nil {
		return "", errors.New("failed to check if file exist: " + err.Error())
	}
	return "", fmt.Errorf("file already exist, we refuse to overwrite '%s'", fn)
}

// LoadConfig returns a config read from the file and an initialized
// Client that can be used to communicate with ByzCoin.
func LoadConfig(file string) (cfg Config, cl *byzcoin.Client, err error) {
	var cfgBuf []byte
	cfgBuf, err = ioutil.ReadFile(file)
	if err != nil {
		return
	}
	err = protobuf.DecodeWithConstructors(cfgBuf, &cfg,
		network.DefaultConstructors(cothority.Suite))
	if err != nil {
		return
	}
	cl = byzcoin.NewClient(cfg.ByzCoinID, cfg.Roster)
	return
}

// ReadRoster reads a roster file from disk.
func ReadRoster(file string) (r *onet.Roster, err error) {
	in, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("Could not open roster %v: %v", file, err)
	}
	defer in.Close()

	group, err := app.ReadGroupDescToml(in)
	if err != nil {
		return nil, err
	}

	if len(group.Roster.List) == 0 {
		return nil, errors.New("empty roster")
	}
	return group.Roster, nil
}
