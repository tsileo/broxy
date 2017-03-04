package router

import (
	"reflect"
	"testing"
)

// TODO(tsileo): add a bench

var testRoute = []struct {
	path, path2        string
	data, expectedData string
	expectedParams     Params
}{
	{"/hello", "/hello", "hello", "hello", Params{}},
	{"/", "/", "index", "index", Params{}},
	{"/hello/:name", "/hello/thomas", "hellop", "hellok", Params{"name": "thomas"}},
	{"/hello/ok", "/hello/ok", "hellok", "hellop", Params{"name": "ok"}},
	{"/another/page/:foo/:bar", "/another/page/lol/nope", "foobar", "foobar", Params{"foo": "lol", "bar": "nope"}},
	{"not:anamed/parameter", "not:anamed/parameter", "nnp", "nnp", Params{}},
}

func TestRouter(t *testing.T) {
	r := &Router{}
	check := func(path, name string, pExpected Params) {
		route, params := r.Match(path)
		if route != nil && route.(string) != name {
			t.Errorf("got %+v expected \"%s\"", route.(string), name)
		}
		if reflect.DeepEqual(params, pExpected) {
			t.Errorf("got %+v expected %+v", params, pExpected)
		}
	}
	for _, testData := range testRoute {
		r.Add(testData.path, testData.data)
	}
	for _, testData := range testRoute {
		check(testData.path2, testData.data, testData.expectedParams)
	}
}
