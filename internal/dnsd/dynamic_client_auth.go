package dnsd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func signDynamicPayloadWithPrivateKey(privateKeyPath string, payload string) (string, string, error) {
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read private key %s: %w", privateKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse private key %s: %w", privateKeyPath, err)
	}
	sig, err := signer.Sign(rand.Reader, []byte(payload))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign payload with private key %s: %w", privateKeyPath, err)
	}
	sigRaw := ssh.Marshal(sig)
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return pub, base64.StdEncoding.EncodeToString(sigRaw), nil
}

func signDynamicPayloadWithAgent(payload string) (string, string, error) {
	sock := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if sock == "" {
		return "", "", fmt.Errorf("SSH_AUTH_SOCK is not set")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return "", "", fmt.Errorf("failed to connect to ssh-agent: %w", err)
	}
	defer conn.Close()

	agentClient := agent.NewClient(conn)
	signers, err := agentClient.Signers()
	if err != nil {
		return "", "", fmt.Errorf("failed to list ssh-agent signers: %w", err)
	}
	if len(signers) == 0 {
		return "", "", fmt.Errorf("ssh-agent has no loaded keys")
	}

	signer := signers[0]
	sig, err := signer.Sign(rand.Reader, []byte(payload))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign payload with ssh-agent key: %w", err)
	}
	sigRaw := ssh.Marshal(sig)
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return pub, base64.StdEncoding.EncodeToString(sigRaw), nil
}

func BuildDynamicSubmitRequest(payload string, privateKeyPath string, useAgent bool) (DynamicSubmitRequest, error) {
	var (
		pub string
		sig string
		err error
	)

	if strings.TrimSpace(privateKeyPath) != "" {
		pub, sig, err = signDynamicPayloadWithPrivateKey(privateKeyPath, payload)
		if err != nil {
			return DynamicSubmitRequest{}, err
		}
	} else {
		if !useAgent {
			return DynamicSubmitRequest{}, fmt.Errorf("no private key provided and ssh-agent usage disabled")
		}
		pub, sig, err = signDynamicPayloadWithAgent(payload)
		if err != nil {
			return DynamicSubmitRequest{}, err
		}
	}

	return DynamicSubmitRequest{
		PayloadHCL: payload,
		PublicKey:  pub,
		Signature:  sig,
	}, nil
}

func SubmitDynamicPayload(target string, payload string, privateKeyPath string, useAgent bool) (*DynamicSubmitResponse, error) {
	req, err := BuildDynamicSubmitRequest(payload, privateKeyPath, useAgent)
	if err != nil {
		return nil, err
	}
	return submitDynamicOverGRPC(target, req)
}

// signString signs an arbitrary string with the SSH key (private key or agent) and
// returns (pubKey, base64Signature, error).
func signString(signed string, privateKeyPath string, useAgent bool) (pubKey string, sig64 string, err error) {
	if strings.TrimSpace(privateKeyPath) != "" {
		return signDynamicPayloadWithPrivateKey(privateKeyPath, signed)
	}
	if !useAgent {
		return "", "", fmt.Errorf("no private key provided and ssh-agent usage disabled")
	}
	return signDynamicPayloadWithAgent(signed)
}

// CreateACMEToken asks the server to generate a new per-record ACME bearer token for fqdn.
func CreateACMEToken(target, fqdn, privateKeyPath string, useAgent bool) (*AcmeTokenCreateResponse, error) {
	challengeFQDN := acmeChallengeFQDN(fqdn)
	signed := "acme-token-create:" + challengeFQDN
	pub, sig, err := signString(signed, privateKeyPath, useAgent)
	if err != nil {
		return nil, err
	}
	return createACMETokenOverGRPC(target, AcmeTokenCreateRequest{
		FQDN:      fqdn,
		PublicKey: pub,
		Signature: sig,
	})
}

// RevokeACMEToken asks the server to revoke a per-record ACME bearer token.
func RevokeACMEToken(target, token, privateKeyPath string, useAgent bool) (*AcmeTokenRevokeResponse, error) {
	signed := "acme-token-revoke:" + token
	pub, sig, err := signString(signed, privateKeyPath, useAgent)
	if err != nil {
		return nil, err
	}
	return revokeACMETokenOverGRPC(target, AcmeTokenRevokeRequest{
		Token:     token,
		PublicKey: pub,
		Signature: sig,
	})
}

// ListACMETokens asks the server to return all per-record ACME tokens.
func ListACMETokens(target, privateKeyPath string, useAgent bool) (*AcmeTokenListResponse, error) {
	pub, sig, err := signString("acme-token-list", privateKeyPath, useAgent)
	if err != nil {
		return nil, err
	}
	return listACMETokensOverGRPC(target, AcmeTokenListRequest{
		PublicKey: pub,
		Signature: sig,
	})
}
