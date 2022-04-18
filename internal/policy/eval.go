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

var policyPkgRegex = regexp.MustCompile(`^[\w.]+$`)

var errNoResult = errors.New("policy did not return a result")

type Evaluator[I any, O any] struct {
	httpClient *http.Client
	policyURL  *url.URL
	logger     zerolog.Logger
}

func NewEvaluator[I any, O any](opaURL, policyPkg string, logger zerolog.Logger) (*Evaluator[I, O], error) {
	u, err := url.ParseRequestURI(opaURL)
	if err != nil {
		return nil, err
	}

	if !policyPkgRegex.MatchString(policyPkg) {
		return nil, fmt.Errorf("invalid policy package")
	}

	policyURL, err := u.Parse("/v1/data/" + strings.ReplaceAll(policyPkg, ".", "/") + "/analysis")
	if err != nil {
		return nil, err
	}
	logger.Debug().Msgf("will use policy url %s", policyURL.String())

	return &Evaluator[I, O]{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		policyURL: policyURL,
		logger:    logger,
	}, nil
}

func (e Evaluator[I, O]) Eval(ctx context.Context, input I) (output O, err error) {
	inputJSON, err := json.Marshal(policyQueryInput[I]{Input: input})
	if err != nil {
		err = fmt.Errorf("failed to marshal input: %w", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.policyURL.String(), bytes.NewReader(inputJSON))
	if err != nil {
		err = fmt.Errorf("failed to create request: %w", err)
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dtapac")

	res, err := e.httpClient.Do(req)
	if err != nil {
		err = fmt.Errorf("failed to send request: %w", err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected response code: %d", res.StatusCode)
		return
	}

	var queryRes policyQueryResponse[O]
	err = json.NewDecoder(res.Body).Decode(&queryRes)
	if err != nil {
		err = fmt.Errorf("failed to decode response: %w", err)
		return
	}

	if queryRes.Result == nil {
		err = errNoResult
		return
	}

	output = *queryRes.Result
	return
}

type policyQueryInput[I any] struct {
	Input I `json:"input"`
}

type policyQueryResponse[O any] struct {
	Result *O `json:"result"`
}
