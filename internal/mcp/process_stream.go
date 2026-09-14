package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ProcessStreamInput struct {
	Text      string `json:"text" jsonschema:"raw text to process"`
	SplitMode string `json:"split_mode,omitempty" jsonschema:"split mode: sentence or newline"`
	Liaisons  bool   `json:"liaisons,omitempty" jsonschema:"whether to show French liaisons"`
}

type ProcessStreamOutput struct {
	ContentType string `json:"content_type"`
	Data        string `json:"data"`
}

type ProcessStreamServer struct {
	Backend string
	Client  *http.Client
}

func readStream(body io.Reader, contentType string) (string, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}

	// NDJSON : le backend renvoie directement les lignes JSON.
	if strings.Contains(contentType, "application/x-ndjson") {
		return string(data), nil
	}

	// SSE.
	if strings.Contains(contentType, "text/event-stream") {
		return readSSE(bytes.NewReader(data))
	}

	// Fallback : retourner le corps brut.
	return string(data), nil
}

func NewProcessStreamServer(backend string) *ProcessStreamServer {
	return &ProcessStreamServer{
		Backend: strings.TrimRight(backend, "/"),
		Client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (s *ProcessStreamServer) Tool(
	ctx context.Context,
	req *mcp.CallToolRequest,
	input ProcessStreamInput,
) (*mcp.CallToolResult, ProcessStreamOutput, error) {

	if strings.TrimSpace(input.Text) == "" {
		return nil, ProcessStreamOutput{}, fmt.Errorf(
			"text must not be empty",
		)
	}

	if input.SplitMode == "" {
		input.SplitMode = "sentence"
	}

	if input.SplitMode != "sentence" &&
		input.SplitMode != "newline" {
		return nil, ProcessStreamOutput{}, fmt.Errorf(
			"invalid split_mode %q",
			input.SplitMode,
		)
	}

	body := map[string]any{
		"text":       input.Text,
		"split_mode": input.SplitMode,
		"liaisons":   input.Liaisons,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, ProcessStreamOutput{}, err
	}

	url := s.Backend + "/api/process_stream"

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		url,
		bytes.NewReader(payload),
	)
	if err != nil {
		return nil, ProcessStreamOutput{}, err
	}

	httpReq.Header.Set(
		"Content-Type",
		"application/json",
	)

	httpReq.Header.Set(
		"Accept",
		"text/event-stream",
	)

	// On transmettra l'identité établie par la gateway.
	if req.Session != nil {
		// Rien ici pour le moment.
		//
		// L'identité sera ajoutée dans une étape suivante
		// via le contexte HTTP de la gateway.
	}

	resp, err := s.Client.Do(httpReq)
	if err != nil {
		return nil, ProcessStreamOutput{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {

		data, _ := io.ReadAll(
			io.LimitReader(resp.Body, 64*1024),
		)

		return nil, ProcessStreamOutput{}, fmt.Errorf(
			"backend returned HTTP %d: %s",
			resp.StatusCode,
			strings.TrimSpace(string(data)),
		)
	}

	contentType := resp.Header.Get("Content-Type")

    data, err := readStream(resp.Body, contentType)
    if err != nil {
    	return nil, ProcessStreamOutput{}, err
    }
	
	if err != nil {
		return nil, ProcessStreamOutput{}, err
	}

	return nil, ProcessStreamOutput{
		ContentType: resp.Header.Get("Content-Type"),
		Data:        data,
	}, nil
}

func readSSE(r io.Reader) (string, error) {

	scanner := bufio.NewScanner(r)

	// Les événements peuvent contenir des lignes relativement longues.
	scanner.Buffer(
		make([]byte, 64*1024),
		1024*1024,
	)

	var events []string

	for scanner.Scan() {

		line := scanner.Text()

		// On conserve uniquement les données SSE.
		if strings.HasPrefix(line, "data:") {
			data := strings.TrimSpace(
				strings.TrimPrefix(line, "data:"),
			)

			events = append(events, data)
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return strings.Join(events, "\n"), nil
}