package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"
)

var (
	ErrNoDecisionResult = errors.New("decision did not yield any result")
)

type Client struct {
	httpClient *http.Client
	baseURL    *url.URL
}

func NewClient(baseURL string) (*Client, error) {
	bu, err := url.ParseRequestURI(baseURL)
	if err != nil {
		return nil, err
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		baseURL: bu,
	}, nil
}

// Decision queries OPA for a policy decision.
// See: https://www.openpolicyagent.org/docs/latest/rest-api/#data-api
func (c Client) Decision(ctx context.Context, decisionPath string, input any, result any) (err error) {
	decisionURL, err := c.baseURL.Parse(path.Join("/v1/data", decisionPath))
	if err != nil {
		return
	}

	inputJSON, err := json.Marshal(decisionRequest{Input: input})
	if err != nil {
		err = fmt.Errorf("failed to marshal input: %w", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, decisionURL.String(), bytes.NewReader(inputJSON))
	if err != nil {
		err = fmt.Errorf("failed to create request: %w", err)
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dtapac")

	res, err := c.httpClient.Do(req)
	if err != nil {
		err = fmt.Errorf("failed to send request: %w", err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected response code: %d", res.StatusCode)
		return
	}

	var decRes decisionResponse
	err = json.NewDecoder(res.Body).Decode(&decRes)
	if err != nil {
		err = fmt.Errorf("failed to decode response: %w", err)
		return
	}

	if decRes.Result == nil {
		err = ErrNoDecisionResult
		return
	}

	err = json.Unmarshal(*decRes.Result, result)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal result: %w", err)
		return
	}

	return
}

type decisionRequest struct {
	Input any `json:"input"`
}

type decisionResponse struct {
	Result *json.RawMessage `json:"result"`
}
