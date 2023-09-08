package enforcer

import (
	"encoding/json"
	"errors"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

var (
	ErrUndefinedResource = errors.New("undefined resource")
	ErrorUndefinedAction = errors.New("undefined action")
)

// ResourceMap is a map of resources by both name and path.
type ResourceMap struct {
	byName map[ResourceName]*Resource
	byPath map[string]*Resource
}

// ActionSelector is a function that can selects an action from a resource.
type ActionSelector func(*ResourceMap) (Action, error)

// Creates a new resource map.
func NewResourceMap(resources ...*Resource) *ResourceMap {
	resMap := &ResourceMap{
		byName: make(map[ResourceName]*Resource),
		byPath: make(map[string]*Resource),
	}

	for _, resource := range resources {
		resMap.AddResource(resource)
	}

	return resMap
}

// Adds a resource to the map.
func (rm *ResourceMap) AddResource(resource *Resource) {
	if _, ok := rm.byName[resource.Name]; ok {
		log.Panic().
			Str("name", string(resource.Name)).
			Msg("duplicate resource name")
	}

	if _, ok := rm.byPath[resource.Path]; ok {
		log.Panic().
			Str("path", resource.Path).
			Msg("duplicate resource path")
	}

	rm.byName[resource.Name] = resource
	rm.byPath[resource.Path] = resource
}

// Checks whether the map has a resource with the given `name`.
func (rm *ResourceMap) GetResourceByName(name ResourceName) *Resource {
	return rm.byName[name]
}

// Checks whether the map has a resource with the given `path`.
func (rm *ResourceMap) GetResourceByPath(path string) *Resource {
	return rm.byPath[path]
}

// Translate a list of action selectos into a list of actions.
func (rm *ResourceMap) GetActions(
	selectors ...ActionSelector,
) ([]Action, error) {
	actions := make([]Action, len(selectors))

	for i, permFactory := range selectors {
		action, err := permFactory(rm)
		if err != nil {
			return nil, err
		}

		actions[i] = action
	}

	return actions, nil
}

func (rm *ResourceMap) getPermissionOfAction(
	resSelector func(*ResourceMap) *Resource,
	action ActionMethod,
) (Action, error) {
	if res := resSelector(rm); res != nil {
		if perm, ok := res.GetAction(action); ok {
			return perm, nil
		}

		return Action{}, ErrorUndefinedAction
	}

	return Action{}, ErrUndefinedResource
}

// Gets action with the given `key` from the resource
func ByName(name ResourceName, action ActionMethod) ActionSelector {
	return func(rm *ResourceMap) (Action, error) {
		return rm.getPermissionOfAction(func(rm *ResourceMap) *Resource {
			return rm.GetResourceByName(name)
		}, action)
	}
}

// Gets action with the given `key` from the resource
func ByPath(path string, action ActionMethod) ActionSelector {
	return func(rm *ResourceMap) (Action, error) {
		return rm.getPermissionOfAction(func(rm *ResourceMap) *Resource {
			return rm.GetResourceByPath(path)
		}, action)
	}
}

func (rm *ResourceMap) UnmarshalJSON(data []byte) error {
	model := struct {
		Resources []*Resource `json:"resources"`
	}{}

	if err := json.Unmarshal(data, &model); err != nil {
		return err
	}

	*rm = *NewResourceMap(model.Resources...)

	return nil
}

func (rm *ResourceMap) UnmarshalYAML(value *yaml.Node) error {
	model := struct {
		Resources []*Resource `yaml:"resources,flow"`
	}{}

	if err := value.Decode(&model); err != nil {
		return err
	}

	*rm = *NewResourceMap(model.Resources...)

	return nil
}
