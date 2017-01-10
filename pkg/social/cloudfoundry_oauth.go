package social

import (
	"encoding/json"
	"net/http"

	"github.com/grafana/grafana/pkg/models"

	"fmt"
	"golang.org/x/oauth2"
	"strings"
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

	CFResource struct {
		NextURL   string           `json:"next_url"`
		Resources []CFResourceItem `json:"resources"`
	}

	CFResourceItem struct {
		Metadata struct {
			GUID string `json:"guid"`
		} `json:"metadata"`

		Entity struct {
			Name          string `json:"name"`
			OrgGUID       string `json:"organization_guid"`
			Username      string `json:"username"`
			DevelopersURL string `json:"developers_url"`
			AuditorsURL   string `json:"auditors_url"`
			ManagersURL   string `json:"managers_url"`
		} `json:"entity"`
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

func (s *CFOAuth) userOrgs(client *http.Client, user *CFUserInfo) ([]models.CreateOrgUserCommand, error) {
	userOrgs := []models.CreateOrgUserCommand{}

	orgsURL := fmt.Sprintf("%s/v2/users/%s/organizations?q=status:active", s.apiUrl, user.UserID)
	orgs, err := s.resource(client, orgsURL, nil)
	if err != nil {
		return nil, err
	}

	if len(orgs.Resources) == 0 {
		return userOrgs, nil
	}

	spacesURL := fmt.Sprintf("%s/v2/users/%s/spaces", s.apiUrl, user.UserID)
	spaces, err := s.resource(client, spacesURL, nil)
	if err != nil {
		return nil, err
	}

	for _, org := range orgs.Resources {
		for _, space := range spaces.Resources {
			if space.Entity.OrgGUID != org.Metadata.GUID {
				continue
			}

			var role models.RoleType
			for _, req := range []struct {
				url  string
				role models.RoleType
			}{
				{
					url:  space.Entity.AuditorsURL,
					role: models.ROLE_VIEWER,
				},
				{
					url:  space.Entity.DevelopersURL,
					role: models.ROLE_EDITOR,
				},
				{
					url:  space.Entity.ManagersURL,
					role: models.ROLE_ADMIN,
				},
			} {
				ok, err := s.spaceRole(client, s.apiUrl+req.url, user.Username)
				if err != nil {
					return nil, err
				}

				if ok {
					role = req.role
					break
				}
			}

			userOrgs = append(userOrgs, models.CreateOrgUserCommand{
				Name: fmt.Sprintf("%s-%s", org.Entity.Name, space.Entity.Name),
				Role: role,
			})
		}
	}

	if len(userOrgs) == 0 {
		return nil, &AuthError{"user doesn't belong to any groups"}
	}

	return userOrgs, nil
}

func (s *CFOAuth) spaceRole(client *http.Client, url, username string) (bool, error) {
	resource, err := s.resource(client, url, nil)
	if err != nil {
		return false, err
	}

	for _, auditor := range resource.Resources {
		if auditor.Entity.Username == username {
			return true, nil
		}
	}

	return false, nil
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
	next := CFResource{}

	if err := s.request(client, url, &next); err != nil {
		return nil, err
	}

	if prev != nil {
		next.Resources = append(prev.Resources, next.Resources...)
	}

	if next.NextURL != "" {
		return s.resource(client, next.NextURL, &next)
	}

	return &next, nil
}
