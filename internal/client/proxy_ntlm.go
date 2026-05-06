package client

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/bodgit/ntlmssp"
)

const (
	NTLM                    = "NTLM "
	AskingForNTLMProxy      = "proxy-authenticate: ntlm"
	AskingForNegotiateProxy = "proxy-authenticate: negotiate"
)

// ProxyAuthSchemes describes which auth schemes a proxy advertised in a 407
// response. The fields are derived purely from substring matching of the
// (case-folded) Proxy-Authenticate headers; a proxy may advertise several
// schemes simultaneously.
type ProxyAuthSchemes struct {
	NTLM      bool
	Negotiate bool
}

// ClassifyProxyAuth inspects a raw HTTP 407 response (status line plus
// headers, terminated by an empty line) and reports which auth schemes the
// proxy advertised. Used to decide between the static NTLM dance and the
// SSPI/Kerberos path.
func ClassifyProxyAuth(response []byte) ProxyAuthSchemes {
	lower := strings.ToLower(string(response))
	return ProxyAuthSchemes{
		NTLM:      strings.Contains(lower, AskingForNTLMProxy),
		Negotiate: strings.Contains(lower, AskingForNegotiateProxy),
	}
}

func parseNTLMCreds(creds string) (domain, user, pass string, err error) {
	if creds == "" {
		return "", "", "", fmt.Errorf("NTLM credentials not provided. Use --ntlm-proxy-creds in format DOMAIN\\USER:PASS")
	}

	parts := strings.Split(creds, "\\")
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("invalid NTLM credentials format. Expected DOMAIN\\USER:PASS, got %q", creds)
	}

	domain = parts[0]
	// Find the first colon after the domain\user portion
	userPassParts := strings.SplitN(parts[1], ":", 2)
	if len(userPassParts) != 2 {
		return "", "", "", fmt.Errorf("invalid NTLM credentials format. Expected DOMAIN\\USER:PASS, got %q", creds)
	}

	return domain, userPassParts[0], userPassParts[1], nil
}

func getNTLMAuthHeader(ntlm *ntlmssp.Client, challengeResponse []byte) (string, error) {

	if len(challengeResponse) == 0 {
		// Type 1 message - Initial Negotiate
		negotiateMessage, err := ntlm.Authenticate(nil, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create NTLM negotiate message: %v", err)
		}
		return NTLM + base64.StdEncoding.EncodeToString(negotiateMessage), nil
	}

	// Type 3 message - Authentication
	authenticateMessage, err := ntlm.Authenticate(challengeResponse, nil)
	if err != nil {
		return "", fmt.Errorf("failed to process NTLM challenge: %v", err)
	}
	return NTLM + base64.StdEncoding.EncodeToString(authenticateMessage), nil
}
