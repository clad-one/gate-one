package httpbinding_test

import (
	"net/http/httptest"
	"testing"

	"cladone/gate-one/pkg/identityadapter/conformance"
	"cladone/gate-one/pkg/identityadapter/conformance/testadapter"
	"cladone/gate-one/pkg/identityadapter/httpbinding"
)

func TestAC_AUTH_10_HTTPBindingParity(t *testing.T) {
	srv := httptest.NewServer(httpbinding.Server(testadapter.New()))
	t.Cleanup(srv.Close)
	client, err := httpbinding.NewClient(srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	conformance.Run(t, client)
}
