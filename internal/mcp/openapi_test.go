package mcpserver

import (
	"strings"
	"testing"
)

const testOpenAPI = `{
  "openapi": "3.0.3",
  "info": {"title": "Demo API", "version": "1"},
  "servers": [{"url": "http://backend.test/v1"}],
  "paths": {
    "/items/{id}": {
      "parameters": [
        {"name": "id", "in": "path", "required": true,
         "schema": {"type": "string"}}
      ],
      "get": {
        "operationId": "get_item",
        "summary": "Fetch one item",
        "parameters": [
          {"name": "verbose", "in": "query",
           "schema": {"type": "boolean"}},
          {"name": "tag", "in": "query",
           "schema": {"type": "array", "items": {"type": "string"}}},
          {"name": "X-Tenant", "in": "header",
           "description": "tenant selector",
           "schema": {"type": "string"}}
        ],
        "responses": {"200": {"description": "ok"}}
      }
    },
    "/items": {
      "post": {
        "operationId": "create_item",
        "description": "Create an item",
        "requestBody": {
          "required": true,
          "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/Item"}}}
        },
        "responses": {"201": {"description": "created"}}
      }
    },
    "/reserved": {
      "get": {
        "operationId": "reserved_header",
        "parameters": [
          {"name": "Authorization", "in": "header",
           "schema": {"type": "string"}}
        ],
        "responses": {"200": {"description": "ok"}}
      }
    },
    "/bulk": {
      "post": {
        "operationId": "create_bulk",
        "requestBody": {
          "required": false,
          "content": {"application/json": {
            "schema": {"type": "array",
                       "items": {"type": "string"}}}}
        },
        "responses": {"200": {"description": "ok"}}
      }
    }
  },
  "components": {
    "schemas": {
      "Item": {
        "type": "object",
        "discriminator": {"propertyName": "kind"},
        "required": ["name"],
        "properties": {
          "name": {"type": "string"},
          "child": {"$ref": "#/components/schemas/Item"},
          "note": {"type": "string", "nullable": true},
          "xml": {"type": "string"}
        }
      },
      "Unused": {
        "type": "object",
        "properties": {"x": {"type": "string"}}
      }
    }
  }
}`

func mustDoc(t *testing.T) *Document {
	t.Helper()
	doc, err := ParseOpenAPI([]byte(testOpenAPI))
	if err != nil {
		t.Fatalf("ParseOpenAPI: %v", err)
	}
	return doc
}

// TestOperationParameters: path-level parameters are inherited, the
// base path comes from servers[0], and the input schema exposes the
// parameters as top-level arguments.
func TestOperationParameters(t *testing.T) {
	doc := mustDoc(t)

	op, err := doc.Operation(OperationSpec{
		Name: "lookup", OperationID: "get_item"})
	if err != nil {
		t.Fatalf("Operation: %v", err)
	}

	if op.Method != "GET" {
		t.Errorf("Method = %q, want GET", op.Method)
	}
	if op.Path != "/items/{id}" {
		t.Errorf("Path = %q, want /items/{id}", op.Path)
	}
	if op.BasePath != "/v1" {
		t.Errorf("BasePath = %q, want /v1", op.BasePath)
	}
	if op.Description != "Fetch one item" {
		t.Errorf("Description = %q", op.Description)
	}

	props, _ := op.InputSchema["properties"].(map[string]any)
	for _, name := range []string{"id", "verbose", "tag", "X-Tenant"} {
		if _, ok := props[name]; !ok {
			t.Errorf("missing property %q in %v", name, props)
		}
	}

	required, _ := op.InputSchema["required"].([]string)
	if len(required) != 1 || required[0] != "id" {
		t.Errorf("required = %v, want [id]", required)
	}

	if len(op.Parameters) != 4 {
		t.Fatalf("parameters = %d, want 4", len(op.Parameters))
	}
	if op.Parameters[0].In != "path" || !op.Parameters[0].Required {
		t.Errorf("path parameter not marked required: %+v",
			op.Parameters[0])
	}
}

// TestOperationBody: an object request body is flattened into
// top-level arguments (LLM-friendly, and the historical processStream
// shape), its required fields propagate, component schemas used by
// nested properties are moved to $defs (recursion preserved), and
// OpenAPI-only keywords are dropped.
func TestOperationBody(t *testing.T) {
	doc := mustDoc(t)

	op, err := doc.Operation(OperationSpec{
		Name: "create", OperationID: "create_item"})
	if err != nil {
		t.Fatalf("Operation: %v", err)
	}
	if op.Body == nil || !op.Body.Required {
		t.Fatalf("body = %+v, want required", op.Body)
	}
	if op.BodyArgument != "" {
		t.Errorf("BodyArgument = %q, want flattened", op.BodyArgument)
	}

	props, _ := op.InputSchema["properties"].(map[string]any)

	if _, wrapped := props["body"]; wrapped {
		t.Errorf("object body not flattened: %v", props)
	}
	for _, name := range []string{"name", "child", "note", "xml"} {
		if _, ok := props[name]; !ok {
			t.Errorf("missing body property %q: %v", name, props)
		}
	}

	required, _ := op.InputSchema["required"].([]string)
	if len(required) != 1 || required[0] != "name" {
		t.Errorf("required = %v, want [name]", required)
	}

	defs, _ := op.InputSchema["$defs"].(map[string]any)
	if _, ok := defs["Item"]; !ok {
		t.Fatalf("$defs missing Item: %v", defs)
	}
	if _, ok := defs["Unused"]; ok {
		t.Errorf("unused component embedded: %v", defs)
	}

	item, _ := defs["Item"].(map[string]any)
	if _, ok := item["discriminator"]; ok {
		t.Errorf("OpenAPI-only keyword kept in schema: %v", item)
	}

	child, _ := props["child"].(map[string]any)
	if ref, _ := child["$ref"].(string); ref != "#/$defs/Item" {
		t.Errorf("recursive ref = %q, want #/$defs/Item", ref)
	}

	note, _ := props["note"].(map[string]any)
	types, _ := note["type"].([]any)
	if len(types) != 2 || types[1] != "null" {
		t.Errorf("nullable type = %v, want [string null]", note["type"])
	}
}

// TestOperationNonObjectBody: a non-object body stays behind a
// single "body" argument.
func TestOperationNonObjectBody(t *testing.T) {
	doc := mustDoc(t)

	op, err := doc.Operation(OperationSpec{
		Name: "bulk", OperationID: "create_bulk"})
	if err != nil {
		t.Fatalf("Operation: %v", err)
	}

	if op.BodyArgument != "body" {
		t.Errorf("BodyArgument = %q, want body", op.BodyArgument)
	}

	props, _ := op.InputSchema["properties"].(map[string]any)
	if _, ok := props["body"]; !ok {
		t.Errorf("missing body wrapper: %v", props)
	}
	if len(op.BodyRequiredFields) != 0 {
		t.Errorf("unexpected required body fields: %v",
			op.BodyRequiredFields)
	}
}

func TestResolveOperationsErrors(t *testing.T) {
	doc := mustDoc(t)

	if _, err := doc.Operation(OperationSpec{
		Name: "nope", OperationID: "does_not_exist"}); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Errorf("unknown operationId error = %v", err)
	}

	if _, err := doc.Operation(OperationSpec{
		Name: "x", OperationID: "reserved_header"}); err == nil ||
		!strings.Contains(err.Error(), "reserved") {
		t.Errorf("reserved header error = %v", err)
	}

	// Duplicate tool names are refused before any fetch when the
	// document is already loaded; check the empty-URL guard too.
	if _, err := ResolveOperations(nil, "",
		"http://backend.test",
		[]OperationSpec{{Name: "a", OperationID: "get_item"}},
	); err == nil || !strings.Contains(err.Error(), "openapi.url") {
		t.Errorf("missing openapi URL error = %v", err)
	}
}

func TestParseOpenAPIRejectsNonV3(t *testing.T) {
	cases := map[string]string{
		"swagger 2": `{"swagger":"2.0","paths":{}}`,
		"no paths":  `{"openapi":"3.0.0"}`,
		"bad json":  `{`,
	}
	for name, raw := range cases {
		if _, err := ParseOpenAPI([]byte(raw)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestResolveOpenAPIURL: the document URL may be absolute
// (production) or relative to the route backend (demo).
func TestResolveOpenAPIURL(t *testing.T) {
	got := resolveOpenAPIURL(
		"/openapi.json", "http://localhost:3201")
	if got != "http://localhost:3201/openapi.json" {
		t.Errorf("relative URL = %q", got)
	}

	got = resolveOpenAPIURL(
		"http://grammar:8000/openapi.json",
		"http://grammar:8000")
	if got != "http://grammar:8000/openapi.json" {
		t.Errorf("absolute URL = %q", got)
	}
}
