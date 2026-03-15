package dnsd

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type DynamicSubmitRequest struct {
	PayloadHCL string `json:"payload_hcl"`
	PublicKey  string `json:"public_key"`
	Signature  string `json:"signature"`
}

type DynamicSubmitResponse struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

// --- ACME token management (gRPC) -----------------------------------------

type AcmeTokenCreateRequest struct {
	FQDN      string `json:"fqdn"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"` // SSH sig over "acme-token-create:" + canonical fqdn
}

type AcmeTokenCreateResponse struct {
	Token string `json:"token"`
	FQDN  string `json:"fqdn"`
}

type AcmeTokenRevokeRequest struct {
	Token     string `json:"token"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"` // SSH sig over "acme-token-revoke:" + token
}

type AcmeTokenRevokeResponse struct {
	Revoked bool `json:"revoked"`
}

type AcmeTokenListRequest struct {
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"` // SSH sig over "acme-token-list"
}

type AcmeTokenListResponse struct {
	Tokens []ACMETokenEntry `json:"tokens"`
}

type dynamicGRPCService struct {
	cfg *RuntimeConfig
}

type dynamicDNSServiceServer interface {
	Submit(context.Context, *DynamicSubmitRequest) (*DynamicSubmitResponse, error)
	AcmeTokenCreate(context.Context, *AcmeTokenCreateRequest) (*AcmeTokenCreateResponse, error)
	AcmeTokenRevoke(context.Context, *AcmeTokenRevokeRequest) (*AcmeTokenRevokeResponse, error)
	AcmeTokenList(context.Context, *AcmeTokenListRequest) (*AcmeTokenListResponse, error)
}

type dynamicAuthData struct {
	authorizedKeys     map[string]ssh.PublicKey
	trustedUserCAs     map[string]ssh.PublicKey
	allowedEmails      map[string]struct{}
	allowedDomains     map[string]struct{}
	allowedDomainExprs map[string][]groupExpression
}

type groupExpression struct {
	clauses [][]string
}

func parseGroupExpression(input string) (groupExpression, error) {
	raw := strings.ToLower(strings.TrimSpace(input))
	if raw == "" {
		return groupExpression{}, fmt.Errorf("empty expression")
	}
	raw = strings.ReplaceAll(raw, ",", "||")

	clauseParts := strings.Split(raw, "||")
	clauses := make([][]string, 0, len(clauseParts))
	for _, part := range clauseParts {
		trimmedClause := strings.TrimSpace(part)
		if trimmedClause == "" {
			return groupExpression{}, fmt.Errorf("invalid expression clause")
		}

		termParts := strings.Split(trimmedClause, "&&")
		clause := make([]string, 0, len(termParts))
		seen := map[string]struct{}{}
		for _, term := range termParts {
			normalizedTerm := strings.ToLower(strings.TrimSpace(term))
			if normalizedTerm == "" {
				return groupExpression{}, fmt.Errorf("invalid empty group term")
			}
			if strings.ContainsAny(normalizedTerm, "@:/&|") {
				return groupExpression{}, fmt.Errorf("invalid group %q", normalizedTerm)
			}
			if _, ok := seen[normalizedTerm]; ok {
				continue
			}
			seen[normalizedTerm] = struct{}{}
			clause = append(clause, normalizedTerm)
		}
		if len(clause) == 0 {
			return groupExpression{}, fmt.Errorf("invalid expression clause")
		}
		clauses = append(clauses, clause)
	}

	if len(clauses) == 0 {
		return groupExpression{}, fmt.Errorf("empty expression")
	}

	return groupExpression{clauses: clauses}, nil
}

func evalGroupExpression(expr groupExpression, certGroups map[string]struct{}) bool {
	for _, clause := range expr.clauses {
		allPresent := true
		for _, group := range clause {
			if _, ok := certGroups[group]; !ok {
				allPresent = false
				break
			}
		}
		if allPresent {
			return true
		}
	}
	return false
}

func loadAuthorizedKeys(path string) (map[string]ssh.PublicKey, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read authorized keys file %s: %w", path, err)
	}

	allowed := map[string]ssh.PublicKey{}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		allowed[string(pub.Marshal())] = pub
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan authorized keys file %s: %w", path, err)
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("no valid authorized keys found in %s", path)
	}
	return allowed, nil
}

func parseAllowlistEntry(line string) (email string, domain string, groupExpr *groupExpression, err error) {
	v := strings.ToLower(strings.TrimSpace(line))
	if v == "" {
		return "", "", nil, fmt.Errorf("empty entry")
	}
	v = strings.TrimPrefix(v, "mailto:")
	v = strings.Trim(v, "<>")

	base := v
	groupPart := ""
	hasGroupSeparator := false
	if idx := strings.Index(v, ":"); idx >= 0 {
		hasGroupSeparator = true
		base = strings.TrimSpace(v[:idx])
		groupPart = strings.TrimSpace(v[idx+1:])
	}

	if strings.Count(base, "@") == 1 && !strings.HasPrefix(base, "@") {
		if groupPart != "" {
			return "", "", nil, fmt.Errorf("groups are only supported on @domain entries")
		}
		parts := strings.SplitN(base, "@", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || !strings.Contains(parts[1], ".") {
			return "", "", nil, fmt.Errorf("invalid email entry")
		}
		return base, "", nil, nil
	}

	if !strings.HasPrefix(base, "@") {
		return "", "", nil, fmt.Errorf("domain entries must use @domain notation")
	}

	base = strings.TrimPrefix(base, "@")
	if base == "" || strings.Contains(base, "@") || !strings.Contains(base, ".") {
		return "", "", nil, fmt.Errorf("invalid domain entry")
	}

	if groupPart == "" {
		if hasGroupSeparator {
			return "", "", nil, fmt.Errorf("empty group expression")
		}
		return "", base, nil, nil
	}

	expr, parseErr := parseGroupExpression(groupPart)
	if parseErr != nil {
		return "", "", nil, parseErr
	}
	return "", base, &expr, nil
}

func loadAuthorizedEmails(path string) (map[string]struct{}, map[string]struct{}, map[string][]groupExpression, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read authorized emails file %s: %w", path, err)
	}
	emails := map[string]struct{}{}
	domains := map[string]struct{}{}
	domainExpressions := map[string][]groupExpression{}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		email, domain, groupExpr, err := parseAllowlistEntry(line)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid entry in %s at line %d: %q (%v)", path, lineNo, line, err)
		}
		if email != "" {
			emails[email] = struct{}{}
		}
		if domain != "" {
			domains[domain] = struct{}{}
			if groupExpr != nil {
				domainExpressions[domain] = append(domainExpressions[domain], *groupExpr)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to scan authorized emails file %s: %w", path, err)
	}
	if len(emails) == 0 && len(domains) == 0 {
		return nil, nil, nil, fmt.Errorf("no valid authorized emails or domains found in %s", path)
	}
	return emails, domains, domainExpressions, nil
}

func loadDynamicAuthData(grpcCfg GRPCConfig) (*dynamicAuthData, error) {
	out := &dynamicAuthData{
		authorizedKeys:     map[string]ssh.PublicKey{},
		trustedUserCAs:     map[string]ssh.PublicKey{},
		allowedEmails:      map[string]struct{}{},
		allowedDomains:     map[string]struct{}{},
		allowedDomainExprs: map[string][]groupExpression{},
	}

	if strings.TrimSpace(grpcCfg.AuthorizedKeysFile) != "" {
		keys, err := loadAuthorizedKeys(grpcCfg.AuthorizedKeysFile)
		if err != nil {
			return nil, err
		}
		out.authorizedKeys = keys
	}

	if strings.TrimSpace(grpcCfg.TrustedUserCAKeysFile) != "" {
		cas, err := loadAuthorizedKeys(grpcCfg.TrustedUserCAKeysFile)
		if err != nil {
			return nil, fmt.Errorf("failed loading trusted user CA keys: %w", err)
		}
		out.trustedUserCAs = cas
	}

	if strings.TrimSpace(grpcCfg.AuthorizedEmailsFile) != "" {
		emails, domains, domainExpressions, err := loadAuthorizedEmails(grpcCfg.AuthorizedEmailsFile)
		if err != nil {
			return nil, err
		}
		for e := range emails {
			out.allowedEmails[e] = struct{}{}
		}
		for d := range domains {
			out.allowedDomains[d] = struct{}{}
		}
		for d, exprs := range domainExpressions {
			out.allowedDomainExprs[d] = append(out.allowedDomainExprs[d], exprs...)
		}
	}

	if len(out.authorizedKeys) == 0 && len(out.trustedUserCAs) == 0 {
		return nil, fmt.Errorf("at least one auth source is required: authorized_keys_file or trusted_user_ca_keys_file")
	}

	if len(out.trustedUserCAs) > 0 && len(out.allowedEmails) == 0 && len(out.allowedDomains) == 0 {
		return nil, fmt.Errorf("certificate auth requires authorized_emails_file")
	}

	return out, nil
}

func extractCertificateEmails(cert *ssh.Certificate) []string {
	seen := map[string]struct{}{}
	add := func(value string) {
		v := strings.ToLower(strings.TrimSpace(value))
		if v == "" {
			return
		}
		v = strings.TrimPrefix(v, "mailto:")
		v = strings.Trim(v, "<>")
		if strings.Count(v, "@") != 1 {
			return
		}
		parts := strings.SplitN(v, "@", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || !strings.Contains(parts[1], ".") {
			return
		}
		seen[v] = struct{}{}
	}

	for _, principal := range cert.ValidPrincipals {
		add(principal)
	}
	add(cert.KeyId)

	out := make([]string, 0, len(seen))
	for e := range seen {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

func extractCertificateGroups(cert *ssh.Certificate) map[string]struct{} {
	out := map[string]struct{}{}
	if cert == nil {
		return out
	}

	keys := []string{"groups", "oidc-groups", "oidc_groups", "openpubkey-groups", "openpubkey_groups"}
	for _, key := range keys {
		value, ok := cert.Extensions[key]
		if !ok {
			continue
		}
		parts := strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
		})
		for _, part := range parts {
			n := strings.ToLower(strings.TrimSpace(part))
			if n == "" {
				continue
			}
			out[n] = struct{}{}
		}
	}

	return out
}

func verifyCertificateAuth(cert *ssh.Certificate, authData *dynamicAuthData) error {
	if cert.CertType != ssh.UserCert {
		return fmt.Errorf("only SSH user certificates are supported")
	}
	if cert.SignatureKey == nil {
		return fmt.Errorf("certificate has no signature key")
	}

	ca, ok := authData.trustedUserCAs[string(cert.SignatureKey.Marshal())]
	if !ok {
		return fmt.Errorf("certificate signer is not a trusted user CA")
	}

	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			_, found := authData.trustedUserCAs[string(auth.Marshal())]
			return found
		},
		Clock: time.Now,
	}

	emails := extractCertificateEmails(cert)
	certGroups := extractCertificateGroups(cert)
	if len(emails) == 0 {
		return fmt.Errorf("certificate does not contain an email identity")
	}

	for _, email := range emails {
		allowed := false
		if _, ok := authData.allowedEmails[email]; ok {
			allowed = true
		} else {
			parts := strings.SplitN(email, "@", 2)
			if len(parts) == 2 {
				domain := parts[1]
				if _, ok := authData.allowedDomains[domain]; ok {
					requiredExprs := authData.allowedDomainExprs[domain]
					if len(requiredExprs) == 0 {
						allowed = true
					} else {
						for _, expr := range requiredExprs {
							if evalGroupExpression(expr, certGroups) {
								allowed = true
								break
							}
						}
					}
				}
			}
		}
		if !allowed {
			continue
		}
		if err := checker.CheckCert(email, cert); err == nil {
			_ = ca
			return nil
		}
	}

	return fmt.Errorf("certificate email identity is not authorized")
}

func verifyDynamicRequest(req DynamicSubmitRequest, grpcCfg GRPCConfig) error {
	if strings.TrimSpace(req.PayloadHCL) == "" {
		return fmt.Errorf("payload_hcl is required")
	}
	if strings.TrimSpace(req.PublicKey) == "" {
		return fmt.Errorf("public_key is required")
	}
	if strings.TrimSpace(req.Signature) == "" {
		return fmt.Errorf("signature is required")
	}

	authData, err := loadDynamicAuthData(grpcCfg)
	if err != nil {
		return err
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		return fmt.Errorf("invalid public_key: %w", err)
	}

	verifyKey := pub
	if cert, isCert := pub.(*ssh.Certificate); isCert {
		if err := verifyCertificateAuth(cert, authData); err != nil {
			return err
		}
		verifyKey = cert.Key
	} else {
		allowedPub, ok := authData.authorizedKeys[string(pub.Marshal())]
		if !ok {
			return fmt.Errorf("public_key is not authorized")
		}
		verifyKey = allowedPub
	}

	sigRaw, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	var sig ssh.Signature
	if err := ssh.Unmarshal(sigRaw, &sig); err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	if err := verifyKey.Verify([]byte(req.PayloadHCL), &sig); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// verifySignedString verifies that publicKey+signature is a valid SSH signature
// over the given signed string, and that the key is authorized via grpcCfg.
func verifySignedString(signed, publicKey, signature64 string, grpcCfg GRPCConfig) error {
	if strings.TrimSpace(publicKey) == "" {
		return fmt.Errorf("public_key is required")
	}
	if strings.TrimSpace(signature64) == "" {
		return fmt.Errorf("signature is required")
	}

	authData, err := loadDynamicAuthData(grpcCfg)
	if err != nil {
		return err
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return fmt.Errorf("invalid public_key: %w", err)
	}

	verifyKey := pub
	if cert, isCert := pub.(*ssh.Certificate); isCert {
		if err := verifyCertificateAuth(cert, authData); err != nil {
			return err
		}
		verifyKey = cert.Key
	} else {
		allowedPub, ok := authData.authorizedKeys[string(pub.Marshal())]
		if !ok {
			return fmt.Errorf("public_key is not authorized")
		}
		verifyKey = allowedPub
	}

	sigRaw, err := base64.StdEncoding.DecodeString(signature64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigRaw, &sig); err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}
	if err := verifyKey.Verify([]byte(signed), &sig); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

func (s *dynamicGRPCService) AcmeTokenCreate(ctx context.Context, req *AcmeTokenCreateRequest) (*AcmeTokenCreateResponse, error) {
	_ = ctx
	if s.cfg.Server.GRPC == nil {
		return nil, fmt.Errorf("grpc not configured")
	}
	fqdn := acmeChallengeFQDN(req.FQDN)
	signed := "acme-token-create:" + fqdn
	if err := verifySignedString(signed, req.PublicKey, req.Signature, *s.cfg.Server.GRPC); err != nil {
		return nil, err
	}
	entry, err := s.cfg.createACMEToken(fqdn)
	if err != nil {
		return nil, err
	}
	return &AcmeTokenCreateResponse{Token: entry.Token, FQDN: entry.FQDN}, nil
}

func (s *dynamicGRPCService) AcmeTokenRevoke(ctx context.Context, req *AcmeTokenRevokeRequest) (*AcmeTokenRevokeResponse, error) {
	_ = ctx
	if s.cfg.Server.GRPC == nil {
		return nil, fmt.Errorf("grpc not configured")
	}
	signed := "acme-token-revoke:" + req.Token
	if err := verifySignedString(signed, req.PublicKey, req.Signature, *s.cfg.Server.GRPC); err != nil {
		return nil, err
	}
	if err := s.cfg.revokeACMEToken(req.Token); err != nil {
		return nil, err
	}
	return &AcmeTokenRevokeResponse{Revoked: true}, nil
}

func (s *dynamicGRPCService) AcmeTokenList(ctx context.Context, req *AcmeTokenListRequest) (*AcmeTokenListResponse, error) {
	_ = ctx
	if s.cfg.Server.GRPC == nil {
		return nil, fmt.Errorf("grpc not configured")
	}
	if err := verifySignedString("acme-token-list", req.PublicKey, req.Signature, *s.cfg.Server.GRPC); err != nil {
		return nil, err
	}
	return &AcmeTokenListResponse{Tokens: s.cfg.listACMETokens()}, nil
}

func (s *dynamicGRPCService) Submit(ctx context.Context, req *DynamicSubmitRequest) (*DynamicSubmitResponse, error) {
	_ = ctx
	if err := verifyDynamicRequest(*req, *s.cfg.Server.GRPC); err != nil {
		observeDynamicSubmission("rejected")
		return nil, err
	}
	id, path, err := submitDynamicPayload(s.cfg, req.PayloadHCL)
	if err != nil {
		observeDynamicSubmission("error")
		return nil, err
	}
	observeDynamicSubmission("accepted")
	return &DynamicSubmitResponse{
		ID:      id,
		Path:    path,
		Message: "dynamic payload accepted",
	}, nil
}

func startDynamicGRPCServer(cfg *RuntimeConfig, configDir string, errCh chan<- error) error {
	_ = configDir
	grpcCfg := cfg.Server.GRPC
	if grpcCfg == nil {
		return nil
	}
	if strings.TrimSpace(grpcCfg.Addr) == "" {
		return fmt.Errorf("server.grpc.addr is required")
	}
	if grpcCfg.Port == 0 {
		return fmt.Errorf("server.grpc.port must be > 0")
	}
	if _, err := loadDynamicAuthData(*grpcCfg); err != nil {
		return err
	}
	acl, err := parseRequiredACL(grpcCfg.Allow, grpcCfg.Deny, "server.grpc")
	if err != nil {
		return err
	}

	network := strings.TrimSpace(grpcCfg.Net)
	if network == "" {
		network = "tcp"
	}
	listenAddr := net.JoinHostPort(strings.TrimSpace(grpcCfg.Addr), fmt.Sprintf("%d", grpcCfg.Port))
	lis, err := net.Listen(network, listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start grpc listener on %s/%s: %w", network, listenAddr, err)
	}

	codec := jsonCodec{}
	encoding.RegisterCodec(codec)
	interceptor := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		p, ok := peer.FromContext(ctx)
		if !ok || p == nil || p.Addr == nil {
			return nil, status.Error(codes.PermissionDenied, "grpc request refused by acl")
		}
		allowed, err := acl.allowsRemote(p.Addr)
		if err != nil {
			logger.Error().Err(err).Str("remote", p.Addr.String()).Msg("grpc acl evaluation failed")
			return nil, status.Error(codes.PermissionDenied, "grpc request refused by acl")
		}
		if !allowed {
			logger.Warn().Str("remote", p.Addr.String()).Msg("grpc request refused by acl")
			return nil, status.Error(codes.PermissionDenied, "grpc request refused by acl")
		}
		return handler(ctx, req)
	}
	server := grpc.NewServer(grpc.ForceServerCodec(codec), grpc.UnaryInterceptor(interceptor))
	svc := &dynamicGRPCService{cfg: cfg}

	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "dnsd.DynamicDNS",
		HandlerType: (*dynamicDNSServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Submit",
				Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					in := new(DynamicSubmitRequest)
					if err := dec(in); err != nil {
						return nil, err
					}
					if interceptor == nil {
						return srv.(dynamicDNSServiceServer).Submit(ctx, in)
					}
					info := &grpc.UnaryServerInfo{
						Server:     srv,
						FullMethod: "/dnsd.DynamicDNS/Submit",
					}
					handler := func(ctx context.Context, req any) (any, error) {
						return srv.(dynamicDNSServiceServer).Submit(ctx, req.(*DynamicSubmitRequest))
					}
					return interceptor(ctx, in, info, handler)
				},
			},
		},
	}, svc)

	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "dnsd.ACMETokens",
		HandlerType: (*dynamicDNSServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Create",
				Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					in := new(AcmeTokenCreateRequest)
					if err := dec(in); err != nil {
						return nil, err
					}
					if interceptor == nil {
						return srv.(dynamicDNSServiceServer).AcmeTokenCreate(ctx, in)
					}
					info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/dnsd.ACMETokens/Create"}
					handler := func(ctx context.Context, req any) (any, error) {
						return srv.(dynamicDNSServiceServer).AcmeTokenCreate(ctx, req.(*AcmeTokenCreateRequest))
					}
					return interceptor(ctx, in, info, handler)
				},
			},
			{
				MethodName: "Revoke",
				Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					in := new(AcmeTokenRevokeRequest)
					if err := dec(in); err != nil {
						return nil, err
					}
					if interceptor == nil {
						return srv.(dynamicDNSServiceServer).AcmeTokenRevoke(ctx, in)
					}
					info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/dnsd.ACMETokens/Revoke"}
					handler := func(ctx context.Context, req any) (any, error) {
						return srv.(dynamicDNSServiceServer).AcmeTokenRevoke(ctx, req.(*AcmeTokenRevokeRequest))
					}
					return interceptor(ctx, in, info, handler)
				},
			},
			{
				MethodName: "List",
				Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					in := new(AcmeTokenListRequest)
					if err := dec(in); err != nil {
						return nil, err
					}
					if interceptor == nil {
						return srv.(dynamicDNSServiceServer).AcmeTokenList(ctx, in)
					}
					info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/dnsd.ACMETokens/List"}
					handler := func(ctx context.Context, req any) (any, error) {
						return srv.(dynamicDNSServiceServer).AcmeTokenList(ctx, req.(*AcmeTokenListRequest))
					}
					return interceptor(ctx, in, info, handler)
				},
			},
		},
	}, svc)

	logger.Info().
		Str("addr", listenAddr).
		Str("net", network).
		Msg("starting dynamic grpc listener")
	go func() {
		errCh <- server.Serve(lis)
	}()
	return nil
}

func submitDynamicOverGRPC(target string, req DynamicSubmitRequest) (*DynamicSubmitResponse, error) {
	codec := jsonCodec{}
	encoding.RegisterCodec(codec)
	conn, err := grpc.Dial(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(codec)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect grpc target %s: %w", target, err)
	}
	defer conn.Close()

	resp := new(DynamicSubmitResponse)
	if err := conn.Invoke(context.Background(), "/dnsd.DynamicDNS/Submit", &req, resp); err != nil {
		return nil, fmt.Errorf("grpc submit failed: %w", err)
	}
	return resp, nil
}

func acmeTokenGRPCConn(target string) (*grpc.ClientConn, error) {
	codec := jsonCodec{}
	encoding.RegisterCodec(codec)
	return grpc.Dial(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(codec)),
	)
}

func createACMETokenOverGRPC(target string, req AcmeTokenCreateRequest) (*AcmeTokenCreateResponse, error) {
	conn, err := acmeTokenGRPCConn(target)
	if err != nil {
		return nil, fmt.Errorf("failed to connect grpc target %s: %w", target, err)
	}
	defer conn.Close()
	resp := new(AcmeTokenCreateResponse)
	if err := conn.Invoke(context.Background(), "/dnsd.ACMETokens/Create", &req, resp); err != nil {
		return nil, fmt.Errorf("grpc acme token create failed: %w", err)
	}
	return resp, nil
}

func revokeACMETokenOverGRPC(target string, req AcmeTokenRevokeRequest) (*AcmeTokenRevokeResponse, error) {
	conn, err := acmeTokenGRPCConn(target)
	if err != nil {
		return nil, fmt.Errorf("failed to connect grpc target %s: %w", target, err)
	}
	defer conn.Close()
	resp := new(AcmeTokenRevokeResponse)
	if err := conn.Invoke(context.Background(), "/dnsd.ACMETokens/Revoke", &req, resp); err != nil {
		return nil, fmt.Errorf("grpc acme token revoke failed: %w", err)
	}
	return resp, nil
}

func listACMETokensOverGRPC(target string, req AcmeTokenListRequest) (*AcmeTokenListResponse, error) {
	conn, err := acmeTokenGRPCConn(target)
	if err != nil {
		return nil, fmt.Errorf("failed to connect grpc target %s: %w", target, err)
	}
	defer conn.Close()
	resp := new(AcmeTokenListResponse)
	if err := conn.Invoke(context.Background(), "/dnsd.ACMETokens/List", &req, resp); err != nil {
		return nil, fmt.Errorf("grpc acme token list failed: %w", err)
	}
	return resp, nil
}
