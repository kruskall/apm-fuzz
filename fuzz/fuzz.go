package fuzz

import (
	"encoding/json"
	"fmt"

	"github.com/google/gofuzz"
	rumv3 "github.com/kruskall/apm-fuzz/internal/rumv3"
	v2 "github.com/kruskall/apm-fuzz/internal/v2"
)

func GenerateIntakeV2Data(data []byte, opts ...Option) ([]byte, error) {
	fuzzer := newFuzzer(data, opts...)

	out, err := generateData(fuzzer,
		&v2.MetadataRoot{},
		&v2.ErrorRoot{},
		&v2.MetricsetRoot{},
		&v2.SpanRoot{},
		&v2.TransactionRoot{},
		&v2.LogRoot{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate v2 intake data: %w", err)
	}

	return out, nil
}

func GenerateRumv3Data(data []byte, opts ...Option) ([]byte, error) {
	fuzzer := newFuzzer(data, opts...)

	out, err := generateData(fuzzer,
		&rumv3.MetadataRoot{},
		&rumv3.TransactionRoot{},
		&rumv3.ErrorRoot{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rumv3 intake data: %w", err)
	}

	return out, nil
}

func newFuzzer(data []byte, opts ...Option) *fuzz.Fuzzer {
	conf := defaultConfig()
	for _, opt := range opts {
		opt(conf)
	}

	fuzzer := fuzz.NewFromGoFuzz(data).
		NilChance(conf.nilChance).
		AllowUnexportedFields(conf.allowUnexportedFields).
		MaxDepth(conf.maxDepth).
		Funcs(func(a *any, c fuzz.Continue) {
			switch c.Intn(6) {
			case 0:
				*a = c.RandString()
			case 1:
				*a = c.Float64()
			case 2:
				*a = []any{c.Float64(), c.RandString(), nil}
			case 3:
				*a = map[string]any{
					c.RandString(): c.Float64(),
					c.RandString(): c.RandString(),
					c.RandString(): c.Int(),
					c.RandString(): nil,
					c.RandString(): []string{c.RandString()},
				}
			case 4:
				*a = []any{
					c.Float64(),
					nil,
					[]any{c.Float64(), c.RandString(), nil},
					map[string]any{
						c.RandString(): []string{c.RandString()},
						c.RandString(): c.RandString(),
						c.RandString(): c.Int(),
						c.RandString(): nil,
					},
				}
			case 5:
				*a = nil
			}
		})

	return fuzzer
}

func generateData(fuzzer *fuzz.Fuzzer, models ...any) ([]byte, error) {
	var out []byte

	for _, model := range models {
		fuzzer.Fuzz(model)

		b, err := json.Marshal(model)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal model %T: %w", model, err)
		}

		out = append(out, b...)
		out = append(out, '\n')
	}

	return out, nil
}
