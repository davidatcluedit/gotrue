package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

// Kakao

const (
	defaultKakaoAuthBase = "kauth.kakao.com"
	defaultKakaoAPIBase  = "kapi.kakao.com"
)

type kakaoProvider struct {
	*oauth2.Config
	APIHost string
}

type kakaoUser struct {
	ID           int64 `json:"id"`
	KakaoAccount struct {
		Profile struct {
			// Optional
			Nickname string `json:"nickname"`
			// Optional
			ProfileImageURL string `json:"profile_image_url"`
		} `json:"profile"`
		Name string `json:"name"`
		// Optional
		Email           string `json:"email"`
		IsEmailValid    bool   `json:"is_email_valid"`
		IsEmailVerified bool   `json:"is_email_verified"`
	} `json:"kakao_account"`
}

// NewKakaoProvider creates a Kakao account provider.
func NewKakaoProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	apiHost := chooseHost(ext.URL, defaultKakaoAPIBase)
	authHost := chooseHost(ext.URL, defaultKakaoAuthBase)

	oauthScopes := []string{}

	if scopes != "" {
		oauthScopes = strings.Split(scopes, ",")
	}

	return &kakaoProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/oauth/authorize",
				TokenURL: authHost + "/oauth/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		APIHost: apiHost,
	}, nil
}

func (k kakaoProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return k.Exchange(context.Background(), code)
}

func (k kakaoProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var user kakaoUser

	req, err := http.NewRequest("GET", k.APIHost+"/v2/user/me", nil)

	if err != nil {
		return nil, err
	}

	// set headers
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Content-type", "application/x-www-form-urlencoded;charset=utf-8")

	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("a %v error occurred with retrieving user from kakao", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &user)
	if err != nil {
		return nil, err
	}

	isEmailVerified := user.KakaoAccount.IsEmailValid && user.KakaoAccount.IsEmailVerified
	subject := strconv.Itoa(int(user.ID))
	emails := []Email{}
	if isEmailVerified {
		emails = append(emails, Email{
			Email:    user.KakaoAccount.Email,
			Verified: isEmailVerified,
			Primary:  true,
		})
	}

	data := &UserProvidedData{
		Metadata: &Claims{
			Issuer:        k.APIHost,
			Subject:       subject,
			Picture:       user.KakaoAccount.Profile.ProfileImageURL,
			Name:          user.KakaoAccount.Name,
			NickName:      user.KakaoAccount.Profile.Nickname,
			Email:         user.KakaoAccount.Email,
			EmailVerified: isEmailVerified,

			// To be deprecated
			Slug:       user.KakaoAccount.Profile.Nickname,
			AvatarURL:  user.KakaoAccount.Profile.ProfileImageURL,
			FullName:   user.KakaoAccount.Name,
			ProviderId: subject,
		},
		Emails: emails,
	}

	return data, nil
}
