package social

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/grafana/grafana/pkg/models"

	"golang.org/x/oauth2"
)

type (
	CFOAuth struct {
		*oauth2.Config
		uaaUrl             string
		apiUrl             string
		allowSignUp        bool
		defaultEmailDomain string
	}

	CFUserInfo struct {
		UserID   string `json:"user_id"`
		Name     string `json:"name"`
		Username string `json:"user_name"`
		Email    string `json:"email"`
	}

	CFMetadata struct {
		GUID string `json:"guid"`
	}

	CFRole struct {
		Metadata CFMetadata `json:"metadata"`
	}

	CFResource struct {
		NextURL   string `json:"next_url"`
		Resources []struct {
			Metadata CFMetadata `json:"metadata"`
			Entity   struct {
				Name       string   `json:"name"`
				Managers   []CFRole `json:"managers"`
				Developers []CFRole `json:"developers"`
				Auditors   []CFRole `json:"auditors"`
			} `json:"entity"`
		} `json:"resources"`
	}
)

func (s *CFOAuth) Type() int {
	return int(models.CLOUDFOUNDRY)
}

func (s *CFOAuth) Scopes() []string {
	return s.Config.Scopes
}

func (s *CFOAuth) IsEmailAllowed(email string) bool {
	return true
}

func (s *CFOAuth) IsSignupAllowed() bool {
	return s.allowSignUp
}

func (s *CFOAuth) UserInfo(client *http.Client) (*BasicUserInfo, error) {
	user := &CFUserInfo{}
	if err := s.request(client, s.uaaUrl+"/userinfo", user); err != nil {
		return nil, err
	}

	userOrgs, err := s.userOrgs(client, user)
	if err != nil {
		return nil, err
	}

	isAdmin := user.Username == "admin"
	if isAdmin {
		user.Email = "admin@localhost"
	}

	// cf doesn't store user emails and returns username instead
	if !strings.Contains(user.Email, "@") && s.defaultEmailDomain != "" {
		user.Email = user.Email + "@" + s.defaultEmailDomain
	}

	return &BasicUserInfo{
		Name:    user.Name,
		Login:   user.Username,
		Email:   user.Email,
		Orgs:    userOrgs,
		IsAdmin: isAdmin,
	}, nil
}

const spaceURLTpl = "%s/v2/organizations/%s/spaces?order-by=name&inline-relations-depth=1"

func (s *CFOAuth) userOrgs(client *http.Client, user *CFUserInfo) ([]models.CreateOrgUserCommand, error) {
	userOrgs := []models.CreateOrgUserCommand{}

	orgsURL := fmt.Sprintf("%s/v2/users/%s/organizations", s.apiUrl, user.UserID)
	orgs, err := s.resource(client, orgsURL, nil)
	if err != nil {
		return nil, err
	}

	if len(orgs.Resources) == 0 {
		return userOrgs, nil
	}

	for _, org := range orgs.Resources {
		spaceURL := fmt.Sprintf(spaceURLTpl, s.apiUrl, org.Metadata.GUID)

		spaces, err := s.resource(client, spaceURL, nil)
		if err != nil {
			return nil, err
		}

		for _, space := range spaces.Resources {
		loop:
			for roleType, roles := range map[models.RoleType][]CFRole{
				models.ROLE_ADMIN:  space.Entity.Managers,
				models.ROLE_EDITOR: space.Entity.Developers,
				models.ROLE_VIEWER: space.Entity.Auditors,
			} {
				for _, role := range roles {
					if role.Metadata.GUID == user.UserID {
						userOrgs = append(userOrgs, models.CreateOrgUserCommand{
							Name: fmt.Sprintf("%s-%s", org.Entity.Name, space.Entity.Name),
							Role: roleType,
						})

						break loop
					}
				}
			}
		}
	}

	return userOrgs, nil
}

func (s *CFOAuth) request(client *http.Client, url string, v interface{}) error {
	req, err := client.Get(url)
	if err != nil {
		return err
	}

	defer req.Body.Close()

	if err = json.NewDecoder(req.Body).Decode(v); err != nil {
		return err
	}

	return nil
}

func (s *CFOAuth) resource(client *http.Client, url string, prev *CFResource) (*CFResource, error) {
	next := &CFResource{}

	if err := s.request(client, url, &next); err != nil {
		return nil, err
	}

	if prev != nil {
		next.Resources = append(prev.Resources, next.Resources...)
	}

	if next.NextURL != "" {
		return s.resource(client, next.NextURL, next)
	}

	return next, nil
}
