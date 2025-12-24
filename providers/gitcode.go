package providers

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// GitcodeProvider represents an Gitcode based Identity Provider
type GitcodeProvider struct {
	*ProviderData
	Org   string
	Repo  string
	Token string
	Users []string
}

type userGitcode struct {
	ID    string `json:"id"`
	Login string `json:"login"`
	Email string `json:"email"`
}

var _ Provider = (*GitcodeProvider)(nil)

const (
	gitcodeProviderName = "GitCode"
	gitcodeDefaultScope = "all_user"
)

var (
	// Default Login URL for Gitcode
	// pre-parsed URL of https://gitcode.com/oauth/authorize.
	gitcodeDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "gitcode.com",
		Path:   "/oauth/authorize",
	}
	// Default Redeem URL for GitHub.
	// Pre-parsed URL of https://gitcode.com/oauth/token.
	gitcodeDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "gitcode.com",
		Path:   "/oauth/token",
	}

	// Default Validation URL for GitHub.
	// ValidationURL is the API Base URL.
	// Other API requests are based off of this (eg to fetch users/groups).
	// Pre-parsed URL of https://gitcode.com/api/v5.
	gitcodeDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "api.gitcode.com",
		Path:   "/api/v5",
	}
)

// NewGitcodeProvider  initiates a new GitcodeProvider
func NewGitcodeProvider(p *ProviderData) *GitcodeProvider {
	p.setProviderDefaults(providerDefaults{
		name:        gitcodeProviderName,
		loginURL:    gitcodeDefaultLoginURL,
		redeemURL:   gitcodeDefaultRedeemURL,
		profileURL:  nil,
		validateURL: gitcodeDefaultValidateURL,
		scope:       gitcodeDefaultScope,
	})
	return &GitcodeProvider{ProviderData: p}
}

// GetEmailAddress returns the Account email address
// Deprecated: Migrate to EnrichSession
func (p *GitcodeProvider) GetEmailAddress(_ context.Context, _ *sessions.SessionState) (string, error) {
	return "", nil
}

// Redeem provides a default implementation of the OAuth2 token redemption process
func (p *GitcodeProvider) Redeem(ctx context.Context, redirectURL, code string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	result := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do()
	if result.Error() != nil {
		return nil, result.Error()
	}
	fmt.Println(string(result.Body()))
	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		CreatedAt    string `json:"created_at"`
	}
	err = result.UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}
	timestampNow := time.Now().Unix()
	// 使用 RFC3339Nano 解析（兼容毫秒）
	t, err_ := time.Parse(time.RFC3339Nano, jsonResponse.CreatedAt)
	if err_ != nil {
		fmt.Println("parse created_at error:" + jsonResponse.CreatedAt)
	} else {
		timestampNow = t.Unix()
	}
	expiresTime := timestampNow + jsonResponse.ExpiresIn

	expiresOn := time.Unix(expiresTime, 0)
	ca := time.Unix(timestampNow, 0)
	p.Scope = jsonResponse.Scope
	return &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		RefreshToken: jsonResponse.RefreshToken,
		ExpiresOn:    &expiresOn,
		CreatedAt:    &ca,
	}, nil

}

// EnrichSession updates the User & Email after the initial Redeem
func (p *GitcodeProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	p.Scope = gitcodeDefaultScope
	return p.getUser(ctx, s)
}

func (p *GitcodeProvider) getUser(ctx context.Context, s *sessions.SessionState) error {
	user, err := p.userInfo(ctx, s.AccessToken)
	if err != nil {
		return err
	}
	// determine whether user is belong to org add code on this place
	// Now that we have the username we can check collaborator status
	if !p.isVerifiedUser(user.Login) && p.Org == "" && p.Repo != "" && p.Token != "" {
		if ok, err := p.isCollaborator(ctx, user.Login, p.Token); err != nil || !ok {
			return err
		}
	}

	s.User = user.Login
	s.Email = user.Email
	return nil
}

// RefreshSessionIfNeeded  checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *GitcodeProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || (s.ExpiresOn != nil && s.ExpiresOn.After(time.Now())) || s.RefreshToken == "" {
		return false, nil
	}
	origExpiration := s.ExpiresOn

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	fmt.Printf("refreshed id token %s (expired on %s)\n", s, origExpiration)
	return true, nil
}

func (p *GitcodeProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
	params := url.Values{}
	params.Add("refresh_token", s.RefreshToken)
	params.Add("grant_type", "refresh_token")
	result := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do()
	if result.Error() != nil {
		return result.Error()
	}
	fmt.Println(string(result.Body()))
	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		CreateAt     int64  `json:"create_at"`
	}
	err := result.UnmarshalInto(&jsonResponse)
	if err != nil {
		return err
	}
	expiresTime := jsonResponse.CreateAt + jsonResponse.ExpiresIn
	expiresOn := time.Unix(expiresTime, 0)
	ca := time.Unix(jsonResponse.CreateAt, 0)
	p.Scope = jsonResponse.Scope
	s.RefreshToken = jsonResponse.RefreshToken
	s.ExpiresOn = &expiresOn
	s.CreatedAt = &ca
	return nil
}

func (p *GitcodeProvider) hasUser(ctx context.Context, accessToken string) (bool, error) {
	user, err := p.userInfo(ctx, accessToken)
	if err != nil {
		return false, err
	}
	if p.isVerifiedUser(user.Login) {
		return true, nil
	}
	return false, nil
}

func (p *GitcodeProvider) userInfo(ctx context.Context, accessToken string) (userGitcode, error) {
	var user userGitcode
	endpoint := &url.URL{
		Scheme: p.ValidateURL.Scheme,
		Host:   p.ValidateURL.Host,
		Path:   path.Join(p.ValidateURL.Path, "/user"),
	}
	err := requests.New(endpoint.String()).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+accessToken).
		SetHeader("Content-Type", "application/json;charset=UTF-8").
		Do().
		UnmarshalInto(&user)
	return user, err
}

func (p *GitcodeProvider) isVerifiedUser(username string) bool {
	for _, u := range p.Users {
		if username == u {
			return true
		}
	}
	return false
}

func (p *GitcodeProvider) isCollaborator(ctx context.Context, login string, accessToken string) (bool, error) {
	params := url.Values{}
	params.Add("access_token", accessToken)
	endpoint := &url.URL{
		Scheme:   p.ValidateURL.Scheme,
		Host:     p.ValidateURL.Host,
		Path:     path.Join(p.ValidateURL.Path, "/repos/", p.Repo, "collaborators", login),
		RawQuery: params.Encode(),
	}
	result := requests.New(endpoint.String()).
		WithContext(ctx).
		SetHeader("Content-Type", "application/json;charset=UTF-8").
		Do()
	if result.Error() != nil {
		return false, result.Error()
	}

	if result.StatusCode() != 204 {
		return false, fmt.Errorf("got %d from %q %s",
			result.StatusCode(), endpoint.String(), result.Body())
	}

	logger.Printf("got %d from %q %s", result.StatusCode(), endpoint.String(), result.Body())

	return true, nil

}

func (p *GitcodeProvider) hasOrg(ctx context.Context, accessToken string) (bool, error) {
	type orgsPage []struct {
		Login string `json:"login"`
	}

	var orgs []struct {
		Login string `json:"login"`
	}

	pn := 1
	ppg := 20
	params := url.Values{}
	params.Add("access_token", accessToken)
	for {
		params.Set("page", strconv.Itoa(pn))
		params.Set("per_page", strconv.Itoa(ppg))
		endpoint := &url.URL{
			Scheme:   p.ValidateURL.Scheme,
			Host:     p.ValidateURL.Host,
			Path:     path.Join(p.ValidateURL.Path, "/user/orgs"),
			RawQuery: params.Encode(),
		}
		var op orgsPage
		err := requests.New(endpoint.String()).
			WithContext(ctx).
			SetHeader("Content-Type", "application/json;charset=UTF-8").
			Do().UnmarshalInto(&op)
		if err != nil {
			return false, err
		}
		if len(op) == 0 {
			break
		}
		orgs = append(orgs, op...)
		if len(op) < ppg {
			break
		}
		pn++
	}
	presentOrgs := make([]string, 0, len(orgs))
	for _, org := range orgs {
		if p.Org == org.Login {
			logger.Printf("found gitcode organization: %q", org.Login)
			return true, nil
		}
		presentOrgs = append(presentOrgs, org.Login)
	}

	logger.Printf("missing organization:%q in %v", p.Org, presentOrgs)
	return false, nil
}

func (p *GitcodeProvider) hasRepo(ctx context.Context, accessToken string) (bool, error) {
	type permissions struct {
		Pull bool `json:"pull"`
		Push bool `json:"push"`
	}

	type repository struct {
		Permissions permissions `json:"permissions"`
		Private     bool        `json:"private"`
	}
	endpoint := &url.URL{
		Scheme: p.ValidateURL.Scheme,
		Host:   p.ValidateURL.Host,
		Path:   path.Join(p.ValidateURL.Path, "repos", p.Repo),
	}

	var repo repository
	err := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeGitHubHeader(accessToken)).
		Do().
		UnmarshalInto(&repo)
	if err != nil {
		return false, err
	}

	// Every user can implicitly pull from a public repo, so only grant access
	// if they have push access or the repo is private and they can pull
	return repo.Permissions.Push || (repo.Private && repo.Permissions.Pull), nil
}

// SetRepo configures the target repository and optional token to use
func (p *GitcodeProvider) SetRepo(repo, token string) {
	p.Repo = repo
	p.Token = token
}

// SetUsers configures allowed usernames
func (p *GitcodeProvider) SetUsers(users []string) {
	p.Users = users
}

// SetOrg adds Gitcode org reading parameters to the OAuth2 scope
func (p *GitcodeProvider) SetOrg(org string) {
	p.Org = org
	if org != "" {
		p.Scope += " groups"
	}
}
