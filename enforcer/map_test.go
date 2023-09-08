package enforcer

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNewFromJSON(t *testing.T) {
	const JSON = `
	{
		"resources": [
			{
				"name": "first-resource",
				"path": "/resource/first",
				"actions": [
					{
						"method":"GET",
						"scopes": ["a", "b", "c"]
					}
				]
			},
			{
				"name": "secondResoucre",
				"path": "app.resource.SecondResouce",
				"actions": [
					{
						"method": "ActionHandler",
						"scopes": ["Admin", "Verifier"]
					}
				]
			}
		]
	}
	`

	resMap := ResourceMap{}
	err := json.Unmarshal([]byte(JSON), &resMap)
	require.Nil(t, err)

	firstRes := resMap.GetResourceByName("first-resource")
	require.NotNil(t, firstRes)
	require.Equal(t, ResourceName("first-resource"), firstRes.Name)
	require.Equal(t, "/resource/first", firstRes.Path)
	action, ok := firstRes.GetAction("GET")
	require.True(t, ok)
	require.Equal(t, "first-resource#a,b,c", action.Permission)

	seconRes := resMap.GetResourceByName("secondResoucre")
	require.NotNil(t, seconRes)
	require.Equal(t, ResourceName("secondResoucre"), seconRes.Name)
	require.Equal(t, "app.resource.SecondResouce", seconRes.Path)
	action, ok = seconRes.GetAction("ActionHandler")
	require.True(t, ok)
	require.Equal(t, "secondResoucre#Admin,Verifier", action.Permission)

	thirdRes := resMap.GetResourceByName("third-resource")
	require.Nil(t, thirdRes)
}

func TestNewFromYAML(t *testing.T) {
	const YAML = `
---
resources:
- name: first-resource
  path: "/resource/first"
  actions:
  - method: GET
    scopes:
    - a
    - b
    - c
- name: secondResoucre
  path: app.resource.SecondResouce
  actions:
  - method: ActionHandler
    scopes:
    - Admin
    - Verifier
`

	resMap := ResourceMap{}
	err := yaml.Unmarshal([]byte(YAML), &resMap)
	require.Nil(t, err)

	// for r, res := range resMap.byName {
	// 	log.Panic().Msgf("r=%v: %#v", r, res)
	// }

	firstRes := resMap.GetResourceByName("first-resource")
	require.NotNil(t, firstRes)
	require.Equal(t, ResourceName("first-resource"), firstRes.Name)
	require.Equal(t, "/resource/first", firstRes.Path)
	perm, ok := firstRes.GetAction("GET")
	require.True(t, ok)
	require.Equal(t, "first-resource#a,b,c", perm.Permission)

	seconRes := resMap.GetResourceByName("secondResoucre")
	require.NotNil(t, seconRes)
	require.Equal(t, ResourceName("secondResoucre"), seconRes.Name)
	require.Equal(t, "app.resource.SecondResouce", seconRes.Path)
	perm, ok = seconRes.GetAction("ActionHandler")
	require.True(t, ok)
	require.Equal(t, "secondResoucre#Admin,Verifier", perm)

	thirdRes := resMap.GetResourceByName("third-resource")
	require.Nil(t, thirdRes)
}
