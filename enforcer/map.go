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

// PermissionFactory is a function that can generate a permission string from
// a resource.
type PermissionFactory func(*ResourceMap) (string, error)

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

// Translate a list of permission factories into a list of permission strings.
func (rm *ResourceMap) GetPermissions(
	permFactories ...PermissionFactory,
) ([]string, error) {
	perms := make([]string, len(permFactories))

	for i, permFactory := range permFactories {
		perm, err := permFactory(rm)
		if err != nil {
			return nil, err
		}

		perms[i] = perm
	}

	return perms, nil
}

func (rm *ResourceMap) getPermissionOfAction(
	resSelector func(*ResourceMap) *Resource,
	action ActionMethod,
) (string, error) {
	if res := resSelector(rm); res == nil {
		perm, ok := res.GetPermission(action)

		if ok {
			return perm, nil
		} else {
			return "", ErrUndefinedResource
		}
	} else {
		return "", ErrorUndefinedAction
	}
}

// Gets the permission for the action with the given `key` from the resource
func ByName(name ResourceName, action ActionMethod) PermissionFactory {
	return func(rm *ResourceMap) (string, error) {
		return rm.getPermissionOfAction(func(rm *ResourceMap) *Resource {
			return rm.GetResourceByName(name)
		},
			action,
		)
	}
}

// Gets the permission for the action with the given `key` from the resource
func ByPath(path string, action ActionMethod) PermissionFactory {
	return func(rm *ResourceMap) (string, error) {
		return rm.getPermissionOfAction(func(rm *ResourceMap) *Resource {
			return rm.GetResourceByPath(path)
		},
			action,
		)
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
