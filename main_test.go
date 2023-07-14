package main

import (
	"bytes"
	"flag"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/kruskall/apm-fuzz/fuzz"
)

var (
	u = flag.String("url", os.Getenv("APM_INTAKE_V2_URL"), "")
)

func FuzzAPMIntake(f *testing.F) {
	if *u == "" {
		f.Fatalf("missing APM intake v2 url")
	}

	c := http.Client{}

	f.Fuzz(func(t *testing.T, input []byte) {
		b, err := fuzz.GenerateIntakeV2Data(input)
		if err != nil {
			t.Logf("failed to generate data with input %v: %v", input, err)
			return
		}

		r := bytes.NewReader(b)

		req, err := http.NewRequest(http.MethodPost, *u, r)
		req.Header.Add("Content-Type", "application/x-ndjson")

		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("failed to send request: %v", err)
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("request failed with status code %s: %s", resp.Status, string(respBody))
		}
	})
}
