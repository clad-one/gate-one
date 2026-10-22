// OpenAPI → MCP tools.
//
// A route's mcp policy declares operations by name + operationId
// (see core.MCPPolicy). This file turns those declarations into
// concrete tools by reading the upstream's OpenAPI document (JSON,
// OpenAPI 3.x):
//
//   - operationId → method + path template (+ server base path);
//   - parameters (path/query/header) → top-level tool arguments;
//   - application/json request body → a single "body" argument;
//   - the input JSON schema is derived from the OpenAPI schemas.
//
// Nothing is hard-coded per operation: the same gateway binary can
// expose any documented REST API as MCP.
package mcpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// OperationSpec is one declarative entry of the mcp policy:
// the tool name exposed to clients and the operationId to resolve in
// the OpenAPI document.
type OperationSpec struct {
	Name        string `json:"name"`
	OperationID string `json:"operationId"`
}

// Parameter is a resolved OpenAPI parameter (path, query or header).
type Parameter struct {
	Name        string
	In          string // "path", "query" or "header"
	Required    bool
	Description string
	Schema      map[string]any
}

// Body is a resolved application/json request body.
type Body struct {
	Required    bool
	Description string
	Schema      map[string]any
}

// Operation is a fully resolved REST operation, ready to be exposed
// as an MCP tool.
type Operation struct {
	Name        string
	OperationID string
	Method      string
	Path        string // OpenAPI template, e.g. /items/{id}
	BasePath    string // servers[0].url path (may be empty)
	Description string
	Parameters  []Parameter
	Body        *Body
	InputSchema map[string]any

	// BodyArgument is "body" when the request body is exposed as a
	// single argument (non-object schema). Empty when the body is
	// flattened: its properties then live at the top level, listed
	// in BodyFields.
	BodyArgument string
	BodyFields   []string

	// BodyRequiredFields are the body properties that must be
	// present when the body is flattened.
	BodyRequiredFields []string
}

// Document is a parsed OpenAPI document. Only the parts needed to
// build tools are interpreted; the raw tree is kept for local $ref
// resolution.
type Document struct {
	root     map[string]any
	basePath string
}

// httpMethods are the OpenAPI path-item keys carrying operations,
// in a stable evaluation order.
var httpMethods = []string{
	"get", "post", "put", "patch", "delete", "head", "options",
	"trace",
}

const maxOpenAPIBytes = 16 << 20

// FetchOpenAPI downloads and parses an OpenAPI document. The client
// may be nil (default 10 s timeout).
func FetchOpenAPI(
	client *http.Client,
	openapiURL string,
) (*Document, error) {

	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	resp, err := client.Get(openapiURL)
	if err != nil {
		return nil, fmt.Errorf(
			"openapi: fetch %s: %w", openapiURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf(
			"openapi: fetch %s: HTTP %d", openapiURL, resp.StatusCode)
	}

	raw, err := io.ReadAll(
		io.LimitReader(resp.Body, maxOpenAPIBytes+1))
	if err != nil {
		return nil, fmt.Errorf(
			"openapi: read %s: %w", openapiURL, err)
	}
	if len(raw) > maxOpenAPIBytes {
		return nil, fmt.Errorf(
			"openapi: %s exceeds %d bytes", openapiURL, maxOpenAPIBytes)
	}

	doc, err := ParseOpenAPI(raw)
	if err != nil {
		return nil, fmt.Errorf("openapi: %s: %w", openapiURL, err)
	}
	return doc, nil
}

// ParseOpenAPI parses an OpenAPI 3.x JSON document.
func ParseOpenAPI(raw []byte) (*Document, error) {

	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if v, _ := root["openapi"].(string); v == "" {
		if sw, _ := root["swagger"].(string); sw != "" {
			return nil, fmt.Errorf(
				"Swagger %s is not supported (OpenAPI 3.x required)", sw)
		}
		return nil, fmt.Errorf("missing \"openapi\" version field")
	}

	if _, ok := root["paths"].(map[string]any); !ok {
		return nil, fmt.Errorf("missing \"paths\" object")
	}

	d := &Document{root: root}

	// servers[0].url path is a prefix for every path template. The
	// host of that URL is deliberately ignored: the gateway always
	// calls route.Backend, never a host taken from the document.
	if servers, ok := root["servers"].([]any); ok && len(servers) > 0 {
		if first, ok := servers[0].(map[string]any); ok {
			if s, _ := first["url"].(string); s != "" {
				if u, err := url.Parse(s); err == nil {
					d.basePath = strings.TrimRight(u.Path, "/")
				}
			}
		}
	}

	return d, nil
}

// ResolveOperations builds the tools declared by specs. An empty
// specs list means "no tools" (no OpenAPI fetch). Any other case
// requires a document URL; a missing operationId, a duplicate tool
// name or an unreadable document is an error: the gateway refuses
// the configuration rather than serving a partial tool set.
func ResolveOperations(
	client *http.Client,
	openapiURL string,
	backend string,
	specs []OperationSpec,
) ([]Operation, error) {

	if len(specs) == 0 {
		return nil, nil
	}

	if openapiURL == "" {
		return nil, fmt.Errorf(
			"operations declared but no openapi.url on this host")
	}

	doc, err := fetchOpenAPIWithRetry(
		client, resolveOpenAPIURL(openapiURL, backend))
	if err != nil {
		return nil, err
	}

	ops := make([]Operation, 0, len(specs))
	seen := map[string]bool{}

	for _, spec := range specs {

		if spec.Name == "" || spec.OperationID == "" {
			return nil, fmt.Errorf(
				"operation entry needs both name and operationId")
		}

		if seen[spec.Name] {
			return nil, fmt.Errorf(
				"duplicate tool name %q", spec.Name)
		}
		seen[spec.Name] = true

		op, err := doc.Operation(spec)
		if err != nil {
			return nil, err
		}
		ops = append(ops, *op)
	}

	return ops, nil
}

// resolveOpenAPIURL accepts an absolute URL (production form) or a
// path relative to the route backend (demo form).
func resolveOpenAPIURL(openapiURL, backend string) string {

	if strings.Contains(openapiURL, "://") {
		return openapiURL
	}

	base, err := url.Parse(backend)
	if err != nil {
		return openapiURL
	}

	ref, err := url.Parse(openapiURL)
	if err != nil {
		return openapiURL
	}

	return base.ResolveReference(ref).String()
}

// fetchRetryDelays: a cold start (compose up) may bring the gateway
// up before the upstream is listening. Fail-fast is kept — the
// gateway must expose the declared tools — but a few short retries
// absorb the startup race. A wrong URL still fails in ~15 s at worst
// (3 attempts x 5 s client timeout).
var fetchRetryDelays = []time.Duration{
	0, 500 * time.Millisecond, time.Second,
}

func fetchOpenAPIWithRetry(
	client *http.Client,
	openapiURL string,
) (*Document, error) {

	var last error

	for _, delay := range fetchRetryDelays {
		if delay > 0 {
			time.Sleep(delay)
		}

		doc, err := FetchOpenAPI(client, openapiURL)
		if err == nil {
			return doc, nil
		}
		last = err
	}

	return nil, last
}

// Operation resolves one operationId into a tool definition.
func (d *Document) Operation(spec OperationSpec) (*Operation, error) {

	found, err := d.findOperation(spec.OperationID)
	if err != nil {
		return nil, err
	}

	params, err := d.parameters(found)
	if err != nil {
		return nil, d.opError(spec, err)
	}

	body, err := d.requestBody(found)
	if err != nil {
		return nil, d.opError(spec, err)
	}

	n := &normalizer{doc: d, schemas: d.componentSchemas(),
		used: map[string]bool{}}

	props := map[string]any{}
	var required []string

	for _, p := range params {

		schema, err := n.normalize(p.Schema)
		if err != nil {
			return nil, d.opError(spec, err)
		}

		prop, ok := schema.(map[string]any)
		if !ok {
			prop = map[string]any{"type": "string"}
		}
		if p.Description != "" {
			if _, has := prop["description"]; !has {
				prop["description"] = p.Description
			}
		}
		props[p.Name] = prop
		if p.Required {
			required = append(required, p.Name)
		}
	}

	bodyArg := ""
	var bodyFields, bodyRequired []string

	if body != nil {

		// An object request body is flattened: its properties
		// become top-level tool arguments, which is what an LLM
		// expects ("text", "split_mode"…) and keeps the shape of
		// the historical processStream tool. Non-object bodies
		// (arrays, bare $refs, scalars) stay behind a "body"
		// argument.
		if obj, ok := d.objectSchema(body.Schema); ok {

			schema, err := n.normalize(obj)
			if err != nil {
				return nil, d.opError(spec, err)
			}
			m, _ := schema.(map[string]any)
			objProps, _ := m["properties"].(map[string]any)

			for name, prop := range objProps {
				if _, clash := props[name]; clash {
					return nil, d.opError(spec, fmt.Errorf(
						"body property %q collides with a "+
							"parameter", name))
				}
				props[name] = prop
				bodyFields = append(bodyFields, name)
			}
			sort.Strings(bodyFields)

			if body.Required {
				bodyRequired = stringList(m["required"])
				required = append(required, bodyRequired...)
			}

		} else {

			if _, clash := props["body"]; clash {
				return nil, d.opError(spec, fmt.Errorf(
					"parameter %q collides with the request "+
						"body argument", "body"))
			}

			schema, err := n.normalize(body.Schema)
			if err != nil {
				return nil, d.opError(spec, err)
			}
			prop, ok := schema.(map[string]any)
			if !ok {
				prop = map[string]any{"type": "object"}
			}
			if body.Description != "" {
				if _, has := prop["description"]; !has {
					prop["description"] = body.Description
				}
			}
			props["body"] = prop
			bodyArg = "body"
			if body.Required {
				required = append(required, "body")
			}
		}
	}

	defs, err := n.definitions()
	if err != nil {
		return nil, d.opError(spec, err)
	}

	input := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		input["required"] = required
	}
	if len(defs) > 0 {
		input["$defs"] = defs
	}

	desc := found.description
	if desc == "" {
		desc = fmt.Sprintf("%s %s",
			strings.ToUpper(found.method), found.path)
	}

	return &Operation{
		Name:        spec.Name,
		OperationID: spec.OperationID,
		Method:      strings.ToUpper(found.method),
		Path:        found.path,
		BasePath:    d.basePath,
		Description: desc,
		Parameters:  params,
		Body:        body,
		InputSchema: input,

		BodyArgument:       bodyArg,
		BodyFields:         bodyFields,
		BodyRequiredFields: bodyRequired,
	}, nil
}

func (d *Document) opError(spec OperationSpec, err error) error {
	return fmt.Errorf(
		"operation %q (operationId %q): %w",
		spec.Name, spec.OperationID, err)
}

// foundOperation is the raw material extracted from the document.
type foundOperation struct {
	path        string
	method      string
	raw         map[string]any
	pathParams  []any
	description string
}

func (d *Document) findOperation(
	operationID string,
) (*foundOperation, error) {

	paths, _ := d.root["paths"].(map[string]any)

	// Deterministic scan: map iteration order is random, a
	// duplicated operationId must always name the same paths.
	pathNames := make([]string, 0, len(paths))
	for p := range paths {
		pathNames = append(pathNames, p)
	}
	sort.Strings(pathNames)

	for _, path := range pathNames {

		if strings.HasPrefix(path, "x-") {
			continue
		}

		item, err := d.resolveMaybeRef(paths[path])
		if err != nil {
			return nil, fmt.Errorf(
				"paths %q: %w", path, err)
		}
		itemMap, ok := item.(map[string]any)
		if !ok {
			continue
		}

		var pathParams []any
		if arr, ok := itemMap["parameters"].([]any); ok {
			pathParams = arr
		}

		for _, method := range httpMethods {

			rawOp, ok := itemMap[method]
			if !ok {
				continue
			}
			opMap, ok := rawOp.(map[string]any)
			if !ok {
				continue
			}

			if id, _ := opMap["operationId"].(string); id != operationID {
				continue
			}

			desc, _ := opMap["description"].(string)
			if desc == "" {
				desc, _ = opMap["summary"].(string)
			}

			return &foundOperation{
				path:        path,
				method:      method,
				raw:         opMap,
				pathParams:  pathParams,
				description: desc,
			}, nil
		}
	}

	return nil, fmt.Errorf(
		"operationId %q not found in the OpenAPI document", operationID)
}

func (d *Document) parameters(
	found *foundOperation,
) ([]Parameter, error) {

	// Path-level parameters are inherited; operation-level ones
	// override them by (name, in), as required by OpenAPI.
	var raws []any
	raws = append(raws, found.pathParams...)
	if arr, ok := found.raw["parameters"].([]any); ok {
		raws = append(raws, arr...)
	}

	byKey := map[string]Parameter{}
	var order []string

	for _, raw := range raws {

		resolved, err := d.resolveMaybeRef(raw)
		if err != nil {
			return nil, fmt.Errorf("parameter: %w", err)
		}
		m, ok := resolved.(map[string]any)
		if !ok {
			continue
		}

		name, _ := m["name"].(string)
		in, _ := m["in"].(string)
		if name == "" || in == "" {
			return nil, fmt.Errorf(
				"parameter without name or location")
		}

		switch in {
		case "path", "query", "header":
			// supported
		case "cookie":
			// Cookies are the gateway's session transport: never
			// forwarded to a backend and never exposed as a tool
			// argument.
			continue
		default:
			continue
		}

		required, _ := m["required"].(bool)
		if in == "path" {
			required = true
		}

		if in == "header" && reservedHeaders[strings.ToLower(name)] {
			return nil, fmt.Errorf(
				"header parameter %q is reserved by the gateway", name)
		}

		desc, _ := m["description"].(string)

		schema, ok := m["schema"].(map[string]any)
		if !ok {
			// OpenAPI also allows content-based parameters:
			// take the first schema found.
			schema = schemaFromContent(m["content"])
		}

		key := in + ":" + name
		if _, exists := byKey[key]; !exists {
			order = append(order, key)
		}
		byKey[key] = Parameter{
			Name:        name,
			In:          in,
			Required:    required,
			Description: desc,
			Schema:      schema,
		}
	}

	params := make([]Parameter, 0, len(order))
	for _, key := range order {
		params = append(params, byKey[key])
	}
	return params, nil
}

func (d *Document) requestBody(
	found *foundOperation,
) (*Body, error) {

	raw, ok := found.raw["requestBody"]
	if !ok {
		return nil, nil
	}

	resolved, err := d.resolveMaybeRef(raw)
	if err != nil {
		return nil, fmt.Errorf("requestBody: %w", err)
	}
	m, ok := resolved.(map[string]any)
	if !ok {
		return nil, nil
	}

	required, _ := m["required"].(bool)
	desc, _ := m["description"].(string)

	content, ok := m["content"].(map[string]any)
	if !ok || len(content) == 0 {
		return nil, nil
	}

	// Prefer application/json; otherwise pick the first media type
	// in lexical order (deterministic).
	media := "application/json"
	if _, ok := content[media]; !ok {
		keys := make([]string, 0, len(content))
		for k := range content {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		media = keys[0]
	}

	entry, _ := content[media].(map[string]any)
	schema, ok := entry["schema"].(map[string]any)
	if !ok {
		schema = map[string]any{"type": "object"}
	}

	return &Body{
		Required:    required,
		Description: desc,
		Schema:      schema,
	}, nil
}

func schemaFromContent(v any) map[string]any {

	content, ok := v.(map[string]any)
	if !ok || len(content) == 0 {
		return map[string]any{"type": "string"}
	}

	keys := make([]string, 0, len(content))
	for k := range content {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if entry, ok := content[k].(map[string]any); ok {
			if schema, ok := entry["schema"].(map[string]any); ok {
				return schema
			}
		}
	}

	return map[string]any{"type": "string"}
}

// componentSchemas returns the local schema components (may be nil).
func (d *Document) componentSchemas() map[string]any {

	components, _ := d.root["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	return schemas
}

// resolveMaybeRef returns v, or the target of its local $ref.
func (d *Document) resolveMaybeRef(v any) (any, error) {

	m, ok := v.(map[string]any)
	if !ok {
		return v, nil
	}

	ref, _ := m["$ref"].(string)
	if ref == "" {
		return v, nil
	}

	return d.resolveRef(ref)
}

// resolveRef resolves a local JSON pointer ($ref must start with
// "#/"). External references are refused: the gateway fetches one
// document, not a graph of remote files.
func (d *Document) resolveRef(ref string) (any, error) {

	if !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf(
			"external $ref %q is not supported", ref)
	}

	var cur any = d.root
	for _, tok := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		key := unescapePointer(tok)
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf(
				"$ref %q: %q is not an object", ref, key)
		}
		cur, ok = m[key]
		if !ok {
			return nil, fmt.Errorf(
				"$ref %q: unknown key %q", ref, key)
		}
	}
	return cur, nil
}

// objectSchema follows local $refs and returns the schema when it
// describes an object with properties (the case that can be
// flattened into tool arguments).
func (d *Document) objectSchema(
	schema map[string]any,
) (map[string]any, bool) {

	cur := schema

	for depth := 0; depth < 16; depth++ {
		ref, _ := cur["$ref"].(string)
		if ref == "" {
			break
		}
		resolved, err := d.resolveRef(ref)
		if err != nil {
			return nil, false
		}
		next, ok := resolved.(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}

	if typ, _ := cur["type"].(string); typ != "" && typ != "object" {
		return nil, false
	}

	props, _ := cur["properties"].(map[string]any)
	if len(props) == 0 {
		return nil, false
	}

	return cur, true
}

// stringList converts a normalized JSON array to []string.
func stringList(v any) []string {

	arr, ok := v.([]any)
	if !ok {
		return nil
	}

	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func escapePointer(s string) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func unescapePointer(s string) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(s, "~1", "/"), "~0", "~")
}

// normalizer turns OpenAPI schemas into JSON Schema 2020-12
// fragments. Local component schemas are moved under "$defs" so
// recursive models keep working (inlining a recursive model never
// terminates).
type normalizer struct {
	doc     *Document
	schemas map[string]any
	used    map[string]bool
}

func (n *normalizer) normalize(v any) (any, error) {
	return n.walk(v, nil)
}

func (n *normalizer) walk(
	v any,
	stack map[string]bool,
) (any, error) {

	switch t := v.(type) {

	case map[string]any:

		if ref, ok := t["$ref"].(string); ok {
			return n.ref(ref, stack)
		}

		out := make(map[string]any, len(t))

		for k, val := range t {

			switch k {
			case "xml", "externalDocs", "discriminator":
				// OpenAPI-only schema keywords, not JSON Schema:
				// a strict client may reject them.
				continue
			case "nullable":
				continue // handled below
			}

			// properties / $defs / definitions are maps of NAME
			// → schema: the names are data, never keywords (a
			// property legitimately named "xml" must survive).
			if k == "properties" || k == "$defs" ||
				k == "definitions" {

				sub, ok := val.(map[string]any)
				if !ok {
					out[k] = val
					continue
				}

				names := make(map[string]any, len(sub))
				for name, sv := range sub {
					nv, err := n.walk(sv, stack)
					if err != nil {
						return nil, err
					}
					names[name] = nv
				}
				out[k] = names
				continue
			}

			nv, err := n.walk(val, stack)
			if err != nil {
				return nil, err
			}
			out[k] = nv
		}

		// OpenAPI 3.0 "nullable": true → JSON Schema type union.
		if nullable, _ := t["nullable"].(bool); nullable {
			switch typ := out["type"].(type) {
			case string:
				out["type"] = []any{typ, "null"}
			case []any:
				out["type"] = append(typ, "null")
			}
		}

		return out, nil

	case []any:

		out := make([]any, len(t))
		for i, val := range t {
			nv, err := n.walk(val, stack)
			if err != nil {
				return nil, err
			}
			out[i] = nv
		}
		return out, nil

	default:

		return v, nil
	}
}

const schemaRefPrefix = "#/components/schemas/"

func (n *normalizer) ref(
	ref string,
	stack map[string]bool,
) (any, error) {

	// Component schemas stay by reference, moved to $defs.
	if strings.HasPrefix(ref, schemaRefPrefix) {

		name := unescapePointer(
			strings.TrimPrefix(ref, schemaRefPrefix))
		if _, ok := n.schemas[name]; !ok {
			return nil, fmt.Errorf(
				"$ref %q: unknown schema", ref)
		}

		n.used[name] = true
		return map[string]any{
			"$ref": "#/$defs/" + escapePointer(name),
		}, nil
	}

	// Any other local reference is inlined (parameters,
	// requestBodies, rarely pathItems). Circular chains are an
	// error rather than an infinite loop.
	if stack[ref] {
		return nil, fmt.Errorf("circular $ref %q", ref)
	}

	target, err := n.doc.resolveRef(ref)
	if err != nil {
		return nil, err
	}

	next := make(map[string]bool, len(stack)+1)
	for k := range stack {
		next[k] = true
	}
	next[ref] = true

	return n.walk(target, next)
}

// definitions returns the $defs closure of the schemas referenced so
// far (transitively).
func (n *normalizer) definitions() (map[string]any, error) {

	if len(n.used) == 0 {
		return nil, nil
	}

	out := map[string]any{}

	for {

		progress := false

		// Snapshot: walk() may add entries to used.
		names := make([]string, 0, len(n.used))
		for name := range n.used {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {

			if _, done := out[name]; done {
				continue
			}

			schema, ok := n.schemas[name]
			if !ok {
				return nil, fmt.Errorf(
					"schema %q disappeared from components", name)
			}

			norm, err := n.walk(schema, map[string]bool{
				schemaRefPrefix + name: true,
			})
			if err != nil {
				return nil, fmt.Errorf("schema %q: %w", name, err)
			}

			out[name] = norm
			progress = true
		}

		if !progress {
			break
		}
	}

	return out, nil
}
