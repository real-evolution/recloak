package enforcer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

type (
	// ResourceName is a unique identifier for a resource.
	ResourceName string

	// ActionMethod is a unique identifier for an action.
	ActionMethod string
)

// Resource is a resource that can be accessed using a set of actions.
type Resource struct {
	Name            ResourceName
	Path            string
	Actions         map[ActionMethod]Action
	actionPermCache map[ActionMethod]string
}

// Creates a new resource with the given `key`.
func NewResource(name ResourceName, path string, actions ...Action) *Resource {
	if strings.Count(string(name), "#") > 0 {
		log.Panic().
			Str("name", string(name)).
			Str("path", path).
			Msg("resource names cannot contain '#'")
	}

	actionMap := make(map[ActionMethod]Action)
	for _, action := range actions {
		actionMap[action.Method] = action
	}

	return &Resource{
		Name:            name,
		Path:            path,
		Actions:         actionMap,
		actionPermCache: make(map[ActionMethod]string),
	}
}

// Adds an action to the resource with the given `method` and `scopes`.
func (r *Resource) AddAction(method ActionMethod, scopes ...string) {
	action := NewAction(method, scopes...)

	r.Actions[action.Method] = action
}

// Checks whether the resource has an action with the given `key`.
func (r *Resource) HasAction(method ActionMethod) bool {
	_, ok := r.Actions[method]

	return ok
}

// Gets the action with the given `key` from the resource.
func (r *Resource) GetAction(method ActionMethod) (Action, bool) {
	action, ok := r.Actions[method]

	return action, ok
}

// Gets the permission for the action with the given `key` from the resource.
func (r *Resource) GetPermission(method ActionMethod) (string, bool) {
	perm, isCached := r.actionPermCache[method]

	if !isCached {
		if action, hasAction := r.Actions[method]; hasAction {
			scopesStr := action.getScopesStr()
			permStr := fmt.Sprintf("%s#%s", r.Name, scopesStr)

			r.actionPermCache[method] = permStr
			return permStr, true
		}
	}

	return perm, isCached
}

func (r *Resource) UnmarshalJSON(data []byte) error {
	model := struct {
		Name    ResourceName `json:"name"`
		Path    string       `json:"path"`
		Actions []Action     `json:"actions"`
	}{}

	if err := json.Unmarshal(data, &model); err != nil {
		return err
	}

	*r = *NewResource(model.Name, model.Path, model.Actions...)

	return nil
}

func (r *Resource) UnmarshalYAML(value *yaml.Node) error {
	model := struct {
		Name    ResourceName `yaml:"name"`
		Path    string       `yaml:"path"`
		Actions []Action     `yaml:"actions,flow"`
	}{}

	if err := value.Decode(&model); err != nil {
		return err
	}

	*r = *NewResource(model.Name, model.Path, model.Actions...)

	return nil
}
