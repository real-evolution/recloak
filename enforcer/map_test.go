package enforcer

import (
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewFromJSON(t *testing.T) {
	const JSON = `
	[
		{
			"name": "first-resource",
			"path": "/resource/first",
			"methods": [
				{
					"method":"GET",
					"scopes": ["a", "b", "c"]
				}
			]
		},
		{
			"name": "secondResoucre",
			"path": "app.resource.SecondResouce",
			"methods": [
				{
					"method": "ActionHandler",
					"scopes": ["Admin", "Verifier"]
				}
			]
		}
	]
	`

	resMap := NewResourceMapFromJSON(JSON)

	for k, res := range resMap.byName {
		log.Printf("byName (%v): %v", k, res)

		for k, action := range res.Actions {
			log.Printf("action (%v): %v", k, action)
		}
	}

	firstRes := resMap.GetResourceByName("first-resource")
	require.NotNil(t, firstRes)
	require.Equal(t, ResourceName("first-resource"), firstRes.Name)
	require.Equal(t, "/resource/first", firstRes.Path)
	perm, ok := firstRes.GetPermission("GET")
	require.True(t, ok)
	require.Equal(t, "first-resource#a,b,c", perm)

	seconRes := resMap.GetResourceByName("secondResoucre")
	require.NotNil(t, seconRes)
	require.Equal(t, ResourceName("secondResoucre"), seconRes.Name)
	require.Equal(t, "app.resource.SecondResouce", seconRes.Path)
	perm, ok = seconRes.GetPermission("ActionHandler")
	require.True(t, ok)
	require.Equal(t, "secondResoucre#Admin,Verifier", perm)

	thirdRes := resMap.GetResourceByName("third-resource")
	require.Nil(t, thirdRes)
}
