package recloak

import (
	"fmt"
	"net/url"

	"gopkg.in/yaml.v3"
)

// ClientConfig is a struct to hold Keycloak client configuration.
type ClientConfig struct {
	AuthServerURL string `yaml:"authServerUrl"`
	Realm         string `yaml:"realm"`
	ClientID      string `yaml:"clientId"`
	ClientSecret  string `yaml:"clientSecret"`
}

// NewClientConfigFromURL creates a new `ClientConfig` from the given URL.
//
// The URL must have the following format:
//
//	<scheme>://<client_id>:<client_secret>@<host>[:<port>]/<realm>
func NewClientConfigFromURL(u *url.URL) (*ClientConfig, error) {
	authServerURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	username := u.User.Username()
	password, _ := u.User.Password()
	realm := u.Path

	return &ClientConfig{
		AuthServerURL: authServerURL,
		Realm:         realm,
		ClientID:      username,
		ClientSecret:  password,
	}, nil
}

// ToURL converts the `ClientConfig` to a URL.
func (c *ClientConfig) ToURL() (*url.URL, error) {
	baseURL, err := url.Parse(c.AuthServerURL)
	if err != nil {
		return nil, err
	}

	bURL := url.URL{
		Scheme:  baseURL.Scheme,
		Opaque:  baseURL.Opaque,
		Host:    baseURL.Host,
		Path:    c.Realm,
		RawPath: "",
	}
	bURL.User = url.UserPassword(c.ClientID, c.ClientSecret)

	return &bURL, nil
}

func (c *ClientConfig) UnmarshalYAML(node *yaml.Node) (err error) {
	type clientConfigModel struct {
		AuthServerURL string `yaml:"authServerUrl"`
		Realm         string `yaml:"realm"`
		ClientID      string `yaml:"clientId"`
		ClientSecret  string `yaml:"clientSecret"`
	}

	if node == nil {
		return nil
	}

	switch node.Kind {
	case yaml.ScalarNode:
		url, err := url.Parse(node.Value)
		if err != nil {
			return err
		}

		parsedConfig, err := NewClientConfigFromURL(url)
		if err != nil {
			return err
		}

		*c = *parsedConfig

	case yaml.MappingNode:
		var model clientConfigModel
		if err := node.Decode(&model); err != nil {
			return err
		}

		*c = ClientConfig(model)
	}

	return
}

func (c *ClientConfig) String() string {
	url, err := c.ToURL()
	if err != nil {
		return ""
	}

	return url.Redacted()
}
