package authz

// Resource is a resource that the access to which is controlled by an
// authorization policy.
type Resource struct {
	// The name of the resource.
	Name string `yaml:"name,omitempty"`

	// The display name of the resource.
	DisplayName string `yaml:"displayName,omitempty"`

	// The description of the resource.
	Policy *PolicySpec `yaml:"policy,omitempty"`

	// The description of the resource.
	Children []Resource `yaml:"children,omitempty"`
}
