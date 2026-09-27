package dnsd

import (
	"github.com/nano-container-linux/libdnsd"
)

// Utiliser directement libdnsd.BuildDynamicSubmitRequest et libdnsd.SubmitDynamicPayload

// signString signs an arbitrary string with the SSH key (private key or agent) and
// returns (pubKey, base64Signature, error).
// Utilise la fonction mutualisée de libdnsd

// CreateACMEToken asks the server to generate a new per-record ACME bearer token for fqdn.
func CreateACMEToken(target, fqdn, privateKeyPath string, useAgent bool) (*AcmeTokenCreateResponse, error) {
	challengeFQDN := libdnsd.AcmeChallengeFQDN(fqdn)
	signed := "acme-token-create:" + challengeFQDN
	pub, sig, err := libdnsd.SignString(signed, privateKeyPath, useAgent)
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
	pub, sig, err := libdnsd.SignString(signed, privateKeyPath, useAgent)
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
	pub, sig, err := libdnsd.SignString("acme-token-list", privateKeyPath, useAgent)
	if err != nil {
		return nil, err
	}
	return listACMETokensOverGRPC(target, AcmeTokenListRequest{
		PublicKey: pub,
		Signature: sig,
	})
}
