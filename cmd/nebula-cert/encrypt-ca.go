package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/slackhq/nebula/cert"
)

type encryptCaFlags struct {
	set              *flag.FlagSet
	path             *string
	outKeyPath       *string
	argonMemory      *uint
	argonIterations  *uint
	argonParallelism *uint
}

func newEncryptCaFlags() *encryptCaFlags {
	cf := encryptCaFlags{set: flag.NewFlagSet("encrypt-ca", flag.ContinueOnError)}
	cf.set.Usage = func() {}
	cf.path = cf.set.String("path", "ca.key", "Optional: path to unencrypted private key")
	cf.outKeyPath = cf.set.String("out-key", "ca.key", "Optional: path to write the private key to")
	cf.argonMemory = cf.set.Uint("argon-memory", 2*1024*1024, "Optional: Argon2 memory parameter (in KiB) used for encrypted private key passphrase")
	cf.argonParallelism = cf.set.Uint("argon-parallelism", 4, "Optional: Argon2 parallelism parameter used for encrypted private key passphrase")
	cf.argonIterations = cf.set.Uint("argon-iterations", 1, "Optional: Argon2 iterations parameter used for encrypted private key passphrase")

	return &cf
}

func encryptCa(args []string, out io.Writer, errOut io.Writer, pr PasswordReader) error {
	cf := newEncryptCaFlags()
	err := cf.set.Parse(args)
	if err != nil {
		return err
	}

	if err = mustFlagString("path", cf.outKeyPath); err != nil {
		return err
	}

	if err = mustFlagString("out-key", cf.outKeyPath); err != nil {
		return err
	}

	// load the CA key
	rawKey, err := os.ReadFile(*cf.path)
	if err != nil {
		return fmt.Errorf("unable to read key; %s", err)
	}

	rawPriv, _, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(rawKey)
	if err != nil {
		return fmt.Errorf("error while unmarshaling private key: %s", err)
	}

	kdfParams, err := parseArgonParameters(*cf.argonMemory, *cf.argonParallelism, *cf.argonIterations)
	if err != nil {
		return err
	}

	var passphrase []byte
	for range 5 {
		out.Write([]byte("Enter passphrase: "))
		passphrase, err = pr.ReadPassword()

		if err == ErrNoTerminal {
			return fmt.Errorf("out-key must be encrypted interactively")
		} else if err != nil {
			return fmt.Errorf("error reading passphrase: %s", err)
		}

		if len(passphrase) > 0 {
			break
		}
	}

	if len(passphrase) == 0 {
		return fmt.Errorf("no passphrase specified, remove -encrypt flag to write out-key in plaintext")
	}

	if _, err := os.Stat(*cf.outKeyPath); err == nil && *cf.outKeyPath != *cf.path {
		return fmt.Errorf("refusing to overwrite existing CA key: %s", *cf.outKeyPath)
	}

	b, err := cert.EncryptAndMarshalSigningPrivateKey(curve, rawPriv, passphrase, kdfParams)
	if err != nil {
		return fmt.Errorf("error while encrypting out-key: %s", err)
	}

	err = os.WriteFile(*cf.outKeyPath, b, 0600)
	if err != nil {
		return fmt.Errorf("error while writing out-key: %s", err)
	}

	return nil
}

func encryptCaSummary() string {
	return "encrypt-ca <flags>: encrypt an existing certificate authority private key"
}

func encryptCaHelp(out io.Writer) {
	cf := newEncryptCaFlags()
	out.Write([]byte("Usage of " + os.Args[0] + " " + caSummary() + "\n"))
	cf.set.SetOutput(out)
	cf.set.PrintDefaults()
}
