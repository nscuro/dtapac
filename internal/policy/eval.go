package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

var (
	errInvalidPolicyPkg = errors.New("invalid policy package")
	errNoResult         = errors.New("policy did not return a result")
)

type Evaluator interface {
	Eval(ctx context.Context, input any, result any) error
}

type opaEvaluator struct {
	httpClient *http.Client
	policyURL  *url.URL
	logger     zerolog.Logger
}

func NewOPAEvaluator(opaURL, policyPkg string, logger zerolog.Logger) (Evaluator, error) {
	u, err := url.ParseRequestURI(opaURL)
	if err != nil {
		return nil, err
	}

	if matched, _ := regexp.MatchString(`^[\w.]+$`, policyPkg); !matched {
		return nil, errInvalidPolicyPkg
	}

	policyURL, err := u.Parse("/v1/data/" + strings.ReplaceAll(policyPkg, ".", "/") + "/analysis")
	if err != nil {
		return nil, err
	}
	logger.Debug().Msgf("will use policy url %s", policyURL.String())

	return &opaEvaluator{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		policyURL: policyURL,
		logger:    logger,
	}, nil
}

func (oe opaEvaluator) Eval(ctx context.Context, input any, result any) (err error) {
	inputJSON, err := json.Marshal(policyQueryInput{Input: input})
	if err != nil {
		err = fmt.Errorf("failed to marshal input: %w", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oe.policyURL.String(), bytes.NewReader(inputJSON))
	if err != nil {
		err = fmt.Errorf("failed to create request: %w", err)
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dtapac")

	res, err := oe.httpClient.Do(req)
	if err != nil {
		err = fmt.Errorf("failed to send request: %w", err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected response code: %d", res.StatusCode)
		return
	}

	var queryRes policyQueryResponse
	err = json.NewDecoder(res.Body).Decode(&queryRes)
	if err != nil {
		err = fmt.Errorf("failed to decode response: %w", err)
		return
	}

	if queryRes.Result == nil {
		err = errNoResult
		return
	}

	err = json.Unmarshal(*queryRes.Result, result)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal result: %w", err)
		return
	}

	return
}

type policyQueryInput struct {
	Input any `json:"input"`
}

type policyQueryResponse struct {
	Result *json.RawMessage `json:"result"`
}
