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
	Name    ResourceName
	Path    string
	Actions map[ActionMethod]Action
}

// Creates a new resource with the given `key`.
func NewResource(
	name ResourceName,
	path string,
	actions ...Action,
) *Resource {
	if strings.Count(string(name), "#") > 0 {
		log.Panic().
			Str("name", string(name)).
			Str("path", path).
			Msg("resource names cannot contain '#'")
	}

	actionMap := make(map[ActionMethod]Action)
	for _, action := range actions {
		scopesStr := action.getScopesStr()
		permStr := fmt.Sprintf("%s#%s", name, scopesStr)
		action.Permission = permStr

		actionMap[action.Method] = action
	}

	return &Resource{
		Name:    name,
		Path:    path,
		Actions: actionMap,
	}
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

type resourceModel struct {
	Name    ResourceName `json:"name"    yaml:"name"`
	Path    string       `json:"path"    yaml:"path"`
	Actions []Action     `json:"actions" yaml:"actions,flow"`
}

func (r *Resource) UnmarshalJSON(data []byte) error {
	model := resourceModel{}
	if err := json.Unmarshal(data, &model); err != nil {
		return err
	}

	*r = *NewResource(model.Name, model.Path, model.Actions...)

	return nil
}

func (r *Resource) UnmarshalYAML(value *yaml.Node) error {
	model := resourceModel{}

	if err := value.Decode(&model); err != nil {
		return err
	}

	*r = *NewResource(model.Name, model.Path, model.Actions...)

	return nil
}
