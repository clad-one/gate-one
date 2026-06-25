package proxy

import (
    "bytes"
    "encoding/json"
    "io"
    "net/http"
)

type RequestContext struct {

    Host    string
    Path    string
    Method  string

    Query   map[string]string
    Headers map[string]string
    Body    map[string]any

    UserID   string
    Username string
    Email    string
    Roles    []string

}

func BuildContext(r *http.Request) (*RequestContext, error) {

    ctx := &RequestContext{
        Host:    r.Host,
        Path:    r.URL.Path,
        Method:  r.Method,
        Query:   map[string]string{},
        Headers: map[string]string{},
        Body:    map[string]any{},
    }

    for k := range r.URL.Query() {
        ctx.Query[k] = r.URL.Query().Get(k)
    }

    for k := range r.Header {
        ctx.Headers[k] = r.Header.Get(k)
    }

    if r.Body != nil {

        data, err := io.ReadAll(r.Body)

        if err != nil {
            return nil, err
        }

        r.Body = io.NopCloser(bytes.NewBuffer(data))

        json.Unmarshal(data, &ctx.Body)
    }

    return ctx, nil
}