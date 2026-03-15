// Package issuerclient provides a gRPC client for the vc IssuerService.
//
// This package is self-contained: it uses a local copy of the generated protobuf
// types (internal/gen/issuer/apiv1_issuer) and builds its own gRPC connection,
// avoiding any dependency on the vc module's internal packages.
//
// If the vc module is later moved to a proper public module path (github.com/...),
// this package should be replaced by importing vc/pkg/issuerclient directly.
package issuerclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sirosfoundation/facetec-api/internal/gen/issuer/apiv1_issuer"
)

// TLSConfig holds gRPC connection options for reaching the vc issuer.
type TLSConfig struct {
	Addr         string // gRPC server address, e.g. "issuer:8090"
	TLS          bool
	CAFilePath   string
	CertFilePath string
	KeyFilePath  string
	ServerName   string
}

// MakeSDJWTRequest holds parameters for SD-JWT credential issuance.
type MakeSDJWTRequest struct {
	Scope        string
	DocumentData []byte // JSON-encoded credential subject fields
	VCTM         []byte // optional raw VCTM JSON bytes
}

// MakeSDJWTReply holds the result of SD-JWT credential issuance.
type MakeSDJWTReply struct {
	Credentials            []string
	TokenStatusListSection int64
	TokenStatusListIndex   int64
}

// MakeMDocRequest holds parameters for ISO 18013-5 mDL issuance.
type MakeMDocRequest struct {
	Scope           string
	DocType         string // e.g. "org.iso.18013.5.1.mDL"
	DocumentData    []byte // JSON-encoded mDL fields
	DevicePublicKey []byte // CBOR-encoded COSE_Key (optional)
	DeviceKeyFormat string // "cose", "jwk", or "x509"
}

// MakeMDocReply holds the result of mDL issuance.
type MakeMDocReply struct {
	MDoc              []byte // CBOR-encoded mDoc
	StatusListSection int64
	StatusListIndex   int64
	ValidFrom         string // RFC3339
	ValidUntil        string // RFC3339
}

// MakeVC20Request holds parameters for W3C VCDM 2.0 credential issuance.
type MakeVC20Request struct {
	Scope             string
	DocumentData      []byte
	CredentialTypes   []string
	SubjectDID        string
	Cryptosuite       string
	MandatoryPointers []string
}

// MakeVC20Reply holds the result of W3C VCDM 2.0 credential issuance.
type MakeVC20Reply struct {
	Credential        []byte // JSON-LD credential
	CredentialID      string
	StatusListSection int64
	StatusListIndex   int64
	ValidFrom         string
	ValidUntil        string
}

// Client is a gRPC client for the vc IssuerService.
type Client struct {
	conn   *grpc.ClientConn
	client apiv1_issuer.IssuerServiceClient
}

// New creates a Client connected to the vc issuer gRPC server.
func New(cfg TLSConfig) (*Client, error) {
	conn, err := dial(cfg)
	if err != nil {
		return nil, fmt.Errorf("issuerclient: dial %q: %w", cfg.Addr, err)
	}
	return &Client{
		conn:   conn,
		client: apiv1_issuer.NewIssuerServiceClient(conn),
	}, nil
}

// MakeSDJWT issues an SD-JWT credential.
func (c *Client) MakeSDJWT(ctx context.Context, req MakeSDJWTRequest) (*MakeSDJWTReply, error) {
	resp, err := c.client.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		Scope:        req.Scope,
		DocumentData: req.DocumentData,
		Vctm:         req.VCTM,
	})
	if err != nil {
		return nil, fmt.Errorf("issuerclient: MakeSDJWT: %w", err)
	}
	reply := &MakeSDJWTReply{
		TokenStatusListSection: resp.TokenStatusListSection,
		TokenStatusListIndex:   resp.TokenStatusListIndex,
	}
	for _, cred := range resp.Credentials {
		reply.Credentials = append(reply.Credentials, cred.Credential)
	}
	return reply, nil
}

// MakeMDoc issues an ISO 18013-5 mDL credential.
func (c *Client) MakeMDoc(ctx context.Context, req MakeMDocRequest) (*MakeMDocReply, error) {
	resp, err := c.client.MakeMDoc(ctx, &apiv1_issuer.MakeMDocRequest{
		Scope:           req.Scope,
		DocType:         req.DocType,
		DocumentData:    req.DocumentData,
		DevicePublicKey: req.DevicePublicKey,
		DeviceKeyFormat: req.DeviceKeyFormat,
	})
	if err != nil {
		return nil, fmt.Errorf("issuerclient: MakeMDoc: %w", err)
	}
	return &MakeMDocReply{
		MDoc:              resp.Mdoc,
		StatusListSection: resp.StatusListSection,
		StatusListIndex:   resp.StatusListIndex,
		ValidFrom:         resp.ValidFrom,
		ValidUntil:        resp.ValidUntil,
	}, nil
}

// MakeVC20 issues a W3C VCDM 2.0 Data Integrity credential.
func (c *Client) MakeVC20(ctx context.Context, req MakeVC20Request) (*MakeVC20Reply, error) {
	resp, err := c.client.MakeVC20(ctx, &apiv1_issuer.MakeVC20Request{
		Scope:             req.Scope,
		DocumentData:      req.DocumentData,
		CredentialTypes:   req.CredentialTypes,
		SubjectDid:        req.SubjectDID,
		Cryptosuite:       req.Cryptosuite,
		MandatoryPointers: req.MandatoryPointers,
	})
	if err != nil {
		return nil, fmt.Errorf("issuerclient: MakeVC20: %w", err)
	}
	return &MakeVC20Reply{
		Credential:        resp.Credential,
		CredentialID:      resp.CredentialId,
		StatusListSection: resp.StatusListSection,
		StatusListIndex:   resp.StatusListIndex,
		ValidFrom:         resp.ValidFrom,
		ValidUntil:        resp.ValidUntil,
	}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

func dial(cfg TLSConfig) (*grpc.ClientConn, error) {
	if !cfg.TLS {
		return grpc.NewClient(cfg.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.CAFilePath != "" {
		ca, err := os.ReadFile(cfg.CAFilePath)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("parse CA certificate")
		}
		tlsConfig.RootCAs = pool
	}

	if cfg.CertFilePath != "" && cfg.KeyFilePath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFilePath, cfg.KeyFilePath)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if cfg.ServerName != "" {
		tlsConfig.ServerName = cfg.ServerName
	}

	return grpc.NewClient(cfg.Addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
}
