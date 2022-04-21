package policy

import (
	"context"
)

type Evaluator interface {
	Eval(ctx context.Context, input any, result any) error
}

type nopEvaluator struct {
}

func NewNopEvaluator() Evaluator {
	return &nopEvaluator{}
}

func (n nopEvaluator) Eval(_ context.Context, _ any, _ any) error {
	return nil
}
