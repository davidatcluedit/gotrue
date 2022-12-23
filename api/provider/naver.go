package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

// Naver

const (
	defaultNaverAuthBase = "nid.naver.com"
	defaultNaverAPIBase  = "openapi.naver.com"
)

type naverProvider struct {
	*oauth2.Config
	APIHost string
}

type naverUser struct {
	Response struct {
		ID              string `json:"id"`
		Nickname        string `json:"nickname"`
		Name            string `json:"name"`
		ProfileImageURL string `json:"profile_image"`
		Email           string `json:"email"`
	} `json:"response"`
}

// NewNaverProvider creates a naver account provider.
func NewNaverProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	apiHost := chooseHost(ext.URL, defaultNaverAPIBase)
	authHost := chooseHost(ext.URL, defaultNaverAuthBase)

	oauthScopes := []string{}

	if scopes != "" {
		oauthScopes = strings.Split(scopes, ",")
	}

	return &naverProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/oauth2.0/authorize",
				TokenURL: authHost + "/oauth2.0/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		APIHost: apiHost,
	}, nil
}

func (n naverProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return n.Exchange(context.Background(), code)
}

func (n naverProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var user naverUser

	req, err := http.NewRequest("GET", n.APIHost+"/v1/nid/me", nil)

	if err != nil {
		return nil, err
	}

	// set headers
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("a %v error occurred with retrieving user from naver", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &user)
	if err != nil {
		return nil, err
	}

	if user.Response.Email == "" {
		return nil, errors.New("unable to find email with naver provider")
	}

	data := &UserProvidedData{
		Metadata: &Claims{
			Issuer:        n.APIHost,
			Subject:       user.Response.ID,
			Picture:       user.Response.ProfileImageURL,
			Name:          user.Response.Name,
			NickName:      user.Response.Nickname,
			Email:         user.Response.Email,
			EmailVerified: true,

			// To be deprecated
			Slug:       user.Response.Nickname,
			AvatarURL:  user.Response.ProfileImageURL,
			FullName:   user.Response.Name,
			ProviderId: user.Response.ID,
		},
		Emails: []Email{{
			Email:    user.Response.Email,
			Verified: true,
			Primary:  true,
		}},
	}

	return data, nil
}
