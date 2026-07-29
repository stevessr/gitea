// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package oauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// linuxDoProvider implements the goth.Provider interface for Linux DO OAuth2.
type linuxDoProvider struct {
	name       string
	clientKey  string
	secret     string
	callback   string
	config     *oauth2.Config
	profileURL string
	scopes     []string
}

// NewLinuxDoProvider creates a new Linux Do OAuth2 provider.
func NewLinuxDoProvider(clientKey, secret, callbackURL, authURL, tokenURL, profileURL string, scopes ...string) goth.Provider {
	return &linuxDoProvider{
		name:      "linuxdo",
		clientKey: clientKey,
		secret:    secret,
		callback:  callbackURL,
		config: &oauth2.Config{
			ClientID:     clientKey,
			ClientSecret: secret,
			RedirectURL:  callbackURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
		},
		profileURL: profileURL,
		scopes:     scopes,
	}
}

func (p *linuxDoProvider) Name() string {
	return p.name
}

func (p *linuxDoProvider) SetName(name string) {
	p.name = name
}

func (p *linuxDoProvider) Debug(debug bool) {}

func (p *linuxDoProvider) RefreshToken(token string) (*oauth2.Token, error) {
	// Linux DO supports token refresh using the oauth2 config
	if p.config == nil {
		return nil, errors.New("missing config")
	}
	tok := &oauth2.Token{RefreshToken: token}
	src := p.config.TokenSource(oauth2.NoContext, tok)
	newToken, err := src.Token()
	if err != nil {
		return nil, err
	}
	return newToken, nil
}

func (p *linuxDoProvider) RefreshTokenAvailable() bool {
	return true
}

// BeginAuth starts the authentication process.
func (p *linuxDoProvider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	return &linuxDoSession{
		AuthURL: url,
	}, nil
}

// UnmarshalSession deserializes a session from a string.
func (p *linuxDoProvider) UnmarshalSession(data string) (goth.Session, error) {
	s := &linuxDoSession{}
	err := json.Unmarshal([]byte(data), s)
	return s, err
}

// FetchUser fetches user info from the provider after authentication.
func (p *linuxDoProvider) FetchUser(session goth.Session) (goth.User, error) {
	sess, ok := session.(*linuxDoSession)
	if !ok {
		return goth.User{}, errors.New("invalid session type")
	}

	user := goth.User{
		Provider: p.name,
	}

	if sess.AccessToken == "" {
		return user, errors.New("missing access token")
	}

	user.AccessToken = sess.AccessToken

	// Fetch user info from profile URL using Bearer token
	req, err := http.NewRequest("GET", p.profileURL, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, errors.New("failed to fetch user info: " + resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return user, err
	}

	if err := json.Unmarshal(body, &user.RawData); err != nil {
		return user, err
	}

	// Map common fields from RawData
	if id, ok := user.RawData["id"]; ok {
		switch v := id.(type) {
		case float64:
			user.UserID = strings.TrimRight(strings.TrimRight(
				strings.Replace(json.Number(json.Number(json.RawMessage{}).String()).String(), ".", "", 1), "0"), ".")
		default:
			user.UserID = toString(v)
		}
	}
	if email, ok := user.RawData["email"]; ok {
		user.Email = toString(email)
	}
	if name, ok := user.RawData["name"]; ok {
		user.Name = toString(name)
	} else if username, ok := user.RawData["username"]; ok {
		user.Name = toString(username)
		user.NickName = toString(username)
	}
	if avatar, ok := user.RawData["avatar_url"]; ok {
		user.AvatarURL = toString(avatar)
	}

	return user, nil
}

type linuxDoSession struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    string
}

// GetAuthURL returns the URL for authentication.
func (s *linuxDoSession) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("missing auth URL")
	}
	return s.AuthURL, nil
}

// Marshal serializes the session to a string.
func (s *linuxDoSession) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// String implements the Stringer interface.
func (s *linuxDoSession) String() string {
	return s.Marshal()
}

// Authorize is called after authentication to set the access token.
func (s *linuxDoSession) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p, ok := provider.(*linuxDoProvider)
	if !ok {
		return "", errors.New("invalid provider type")
	}
	token, err := p.config.Exchange(oauth2.NoContext, params.Get("code"))
	if err != nil {
		return "", err
	}
	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	if !token.Expiry.IsZero() {
		s.ExpiresAt = token.Expiry.String()
	}
	return token.AccessToken, nil
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case float64:
		// Remove trailing decimal zeros
		return fmt.Sprintf("%v", s)
	default:
		return fmt.Sprintf("%v", s)
	}
}
