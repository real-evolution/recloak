package enforcer

import (
	"encoding/json"
	"errors"
)

var (
	ErrUndefinedResource = errors.New("undefined resource")
	ErrorUndefinedAction = errors.New("undefined action")
)

// ResourceMap is a map of resources by both name and path.
type ResourceMap struct {
	byName map[ResourceName]Resource
	byPath map[string]Resource
}

// PermissionFactory is a function that can generate a permission string from
// a resource.
type PermissionFactory func(*ResourceMap) (string, error)

// Creates a new resource map.
func NewResourceMap(resources ...Resource) *ResourceMap {
	resMap := &ResourceMap{
		byName: make(map[ResourceName]Resource),
		byPath: make(map[string]Resource),
	}

	for _, resource := range resources {
		resMap.AddResource(resource)
	}

	return resMap
}

// Creates a new resource map from a JSON string.
func NewResourceMapFromJSON(jsonStr string) *ResourceMap {
	resources := make([]Resource, 0)

	json.Unmarshal([]byte(jsonStr), &resources)

	return NewResourceMap(resources...)
}

// Adds a resource to the map.
func (rm *ResourceMap) AddResource(resource Resource) {
	rm.byName[resource.Name] = resource
	rm.byPath[resource.Path] = resource
}

// Checks whether the map has a resource with the given `name`.
func (rm *ResourceMap) GetResourceByName(name ResourceName) (Resource, bool) {
	resource, ok := rm.byName[name]

	return resource, ok
}

// Checks whether the map has a resource with the given `path`.
func (rm *ResourceMap) GetResourceByPath(path string) (Resource, bool) {
	resource, ok := rm.byPath[path]

	return resource, ok
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
	resSelector func(*ResourceMap) (Resource, bool),
	action ActionMethod,
) (string, error) {
	res, ok := resSelector(rm)
	if !ok {
		return "", ErrUndefinedResource
	}

	perm, ok := res.GetPermission(action)
	if !ok {
		return "", ErrorUndefinedAction
	}

	return perm, nil
}

// Gets the permission for the action with the given `key` from the resource
func ByName(name ResourceName, action ActionMethod) PermissionFactory {
	return func(rm *ResourceMap) (string, error) {
		return rm.getPermissionOfAction(func(rm *ResourceMap) (Resource, bool) {
			return rm.GetResourceByName(name)
		},
			action,
		)
	}
}

// Gets the permission for the action with the given `key` from the resource
func ByPath(path string, action ActionMethod) PermissionFactory {
	return func(rm *ResourceMap) (string, error) {
		return rm.getPermissionOfAction(func(rm *ResourceMap) (Resource, bool) {
			return rm.GetResourceByPath(path)
		},
			action,
		)
	}
}
