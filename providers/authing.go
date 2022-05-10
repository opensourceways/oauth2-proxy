package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/Authing/authing-go-sdk/lib/authentication"
	"github.com/Authing/authing-go-sdk/lib/constant"
	"github.com/Authing/authing-go-sdk/lib/model"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

const (
	authingProviderName = "authing"
	authingScope        = "openid profile email phone address"
)

var _ Provider = (*OIDCProvider)(nil)

type userInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

type AuthingProvide struct {
	*ProviderData

	SkipNonce bool
	cli       *authentication.Client
}

func NewAuthingProvide(p *ProviderData) *AuthingProvide {
	p.ProviderName = authingProviderName
	if p.Scope == "" {
		p.Scope = authingScope
	}

	client := authentication.NewClient(p.ClientID, p.ClientSecret)
	client.Protocol = constant.OIDC
	client.TokenEndPointAuthMethod = constant.None

	return &AuthingProvide{
		ProviderData: p,
		SkipNonce:    true,
		cli:          client,
	}
}

func (ap *AuthingProvide) GetLoginURL(redirectURI, state, nonce string) string {
	extraParams := url.Values{}
	if !ap.SkipNonce {
		extraParams.Add("nonce", nonce)
	}
	loginURL := makeLoginURL(ap.Data(), redirectURI, state, extraParams)
	// reset cli host
	ap.cli.Host = fmt.Sprintf("%s://%s", loginURL.Scheme, loginURL.Host)

	return loginURL.String()
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (ap *AuthingProvide) Redeem(_ context.Context, _, code string) (*sessions.SessionState, error) {
	t, err := ap.cli.GetAccessTokenByCode(code)
	var tokenInfo = struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		ExpiresIn    int64  `json:"expires_in"`
		IDToken      string `json:"id_token"`
	}{}

	if err := json.Unmarshal([]byte(t), &tokenInfo); err != nil {
		return nil, err
	}

	if tokenInfo.AccessToken == "" {
		return nil, fmt.Errorf("can't get access token by code: %s", code)
	}

	ap.Scope = tokenInfo.Scope
	sess := &sessions.SessionState{
		RefreshToken: tokenInfo.RefreshToken,
		AccessToken:  tokenInfo.AccessToken,
	}

	sess.CreatedAtNow()
	sess.SetExpiresOn(time.Unix(tokenInfo.ExpiresIn, 0))

	tReq := model.ValidateTokenRequest{IdToken: tokenInfo.IDToken}

	_, err = ap.cli.ValidateToken(tReq)
	if err != nil {
		return nil, err
	}

	u, err := ap.getCurrentUser(sess.AccessToken)
	if err != nil {
		return nil,err
	}

	sess.User = u.Id

	if u.Email != nil {
		sess.Email = *u.Email
	}

	sess.Groups = transformGroups(u)

	return sess, nil
}

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (ap *AuthingProvide) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if s.Email == "" || s.User == "" {
		u, err := ap.getCurrentUser(s.AccessToken)
		if err != nil {
			return err
		}

		s.User = u.Id

		if u.Email != nil {
			s.Email = *u.Email
		}

		s.Groups = transformGroups(u)
	}

	if s.Email == "" && s.User == "" {
		return errors.New("neither the id_token nor the email and sub")
	}

	return nil
}

// ValidateSession validates the AccessToken
func (ap *AuthingProvide) ValidateSession(_ context.Context, s *sessions.SessionState) bool {
	res, err := ap.cli.IntrospectToken(s.AccessToken)
	if err != nil {
		return false
	}

	var info = struct {
		Active bool `json:"active"`
	}{}

	if err := json.Unmarshal([]byte(res), &info); err != nil {
		return false
	}

	return info.Active
}

func (ap *AuthingProvide) getCurrentUser(token string) (*model.User, error) {
	u, err := ap.cli.GetCurrentUser(&token)
	if err != nil {
		return nil, err
	}

	if u == nil {
		return u, errors.New("can't get user info by access token")
	}

	return u, nil
}

func transformGroups(u *model.User) []string {
	if u == nil || u.Groups == nil {
		return nil
	}

	var groups []string

	for _, v := range u.Groups.List {
		groups = append(groups, v.Name)
	}

	return groups
}
