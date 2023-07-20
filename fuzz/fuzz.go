package fuzz

import (
	"encoding/json"
	"fmt"
	"time"

	rumv3 "github.com/kruskall/apm-fuzz/internal/rumv3"
	v2 "github.com/kruskall/apm-fuzz/internal/v2"
	fuzz "github.com/kruskall/go-fuzz-headers"
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

func newFuzzer(data []byte, opts ...Option) *fuzz.ConsumeFuzzer {
	conf := defaultConfig()
	for _, opt := range opts {
		opt(conf)
	}

	fuzzer := fuzz.NewConsumer(data,
		fuzz.WithNilChance(float32(conf.nilChance)),
		fuzz.WithMaxDepth(int64(conf.maxDepth)),
		fuzz.WithUnknownTypeStrategy(fuzz.FailWithError),
		fuzz.WithCustomFunction(fuzzAny),
		fuzz.WithCustomFunction(fuzzTime),
	)

	return fuzzer
}

func fuzzTime(a *time.Time, c fuzz.Continue) error {
	sec, err := c.Source.GetInt()
	if err != nil {
		return err
	}

	nsec, err := c.Source.GetInt()
	if err != nil {
		return err
	}

	*a = time.Unix(int64(sec), int64(nsec))
	return nil
}

func fuzzAny(a *any, c fuzz.Continue) error {
	rnd, err := c.Source.GetByte()
	if err != nil {
		return err
	}

	switch rnd % 5 {
	case 0:
		*a, err = c.Source.GetString()
	case 1:
		*a, err = c.Source.GetFloat64()
	case 2:
		s := make([]any, 0)
		if err = c.GenerateStruct(&s); err == nil {
			*a = s
		}
	case 3:
		m := make(map[string]any)
		if err = c.GenerateStruct(&m); err == nil {
			*a = m
		}
	case 4:
		*a = nil
	}

	return err
}

func generateData(fuzzer *fuzz.ConsumeFuzzer, models ...any) ([]byte, error) {
	var out []byte

	for _, model := range models {
		if err := fuzzer.GenerateStruct(model); err != nil {
			return nil, fmt.Errorf("failed to generate model %T: %w", model, err)
		}

		b, err := json.Marshal(model)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal model %T: %w", model, err)
		}

		out = append(out, b...)
		out = append(out, '\n')
	}

	return out, nil
}
