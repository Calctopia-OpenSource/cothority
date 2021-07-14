package zkPOI

import (
	"go.dedis.ch/onet/v3/network"
	"github.com/google/uuid"
	"go.dedis.ch/kyber/v3"
)

// PROTOSTART
// package zkPOI;
// import "network.proto";
//
// option java_package = "ch.epfl.dedis.lib.proto";
// option java_outer_classname = "zkPOIProto";

// NewPublicKey used for setting authentication
type NewPublicKey struct {
	//Publics   []network.ServerIdentity
	Publics   []ServerIdentityStringified
	Sig       []byte
	ByzcoinID string
}

// Why ServerIdentityStringified instead of network.ServerIdentity:
//  dedis/protobuf is decoding all kyber.Points as ed25519, but ServiceIdentity should be decoded as bn256
//  thus, we need to send ServiceIdentityStringified.Public as string instead of bytes to prevent wrong decoding as ed25519

// ServerIdentity is used to represent a Server in the whole internet.
// It's based on a public key, and there can be one or more addresses to contact it.
type ServerIdentityStringified struct {
	// This is the public key of that ServerIdentity
	Public kyber.Point
	// This is the configuration for the services
	ServiceIdentities []ServiceIdentityStringified
	// The ServerIdentityID corresponding to that public key
	// Deprecated: use GetID
	ID network.ServerIdentityID
	// The address where that Id might be found
	Address network.Address
	// Description of the server
	Description string
	// This is the private key, may be nil. It is not exported so that it will never
	// be marshalled.
	private kyber.Scalar
	// The URL where the WebSocket interface can be found. (If not set, then default is http, on port+1.)
	// optional
	URL string `protobuf:"opt"`
}

// ServerIdentityID uniquely identifies an ServerIdentity struct
type ServerIdentityID uuid.UUID

// ServiceIdentity contains the identity of a service which is its public and
// private keys
type ServiceIdentityStringified struct {
	Name    string
	Suite   string
	Public  string
	private kyber.Scalar
}
