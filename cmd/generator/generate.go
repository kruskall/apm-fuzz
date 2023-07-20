package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

var (
	out = flag.String("out", "", "")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := generateV2(); err != nil {
		return fmt.Errorf("failed to generate v2 model: %w", err)
	}
	if err := generateRumv3(); err != nil {
		return fmt.Errorf("failed to generate v3 model: %w", err)
	}
	return nil
}

func generateV2() error {
	remoteV2 := "https://raw.githubusercontent.com/elastic/apm-data/main/input/elasticapm/internal/modeldecoder/v2/model.go"
	outFile := filepath.Join("v2", "model.go")

	return generateLocalModel(remoteV2, outFile)
}

func generateRumv3() error {
	remoteRumv3 := "https://raw.githubusercontent.com/elastic/apm-data/main/input/elasticapm/internal/modeldecoder/rumv3/model.go"
	outFile := filepath.Join("rumv3", "model.go")

	return generateLocalModel(remoteRumv3, outFile)
}

func generateLocalModel(remoteUrl string, localPath string) error {
	if *out == "" {
		return fmt.Errorf("missing output")
	}
	outBase, err := filepath.Abs(*out)
	if err != nil {
		return fmt.Errorf("failed to retrieve abs path for %s: %w", *out, err)
	}

	modelPath := filepath.Join(outBase, localPath)

	rsp, err := okDo(remoteUrl)
	if err != nil {
		return fmt.Errorf("failed to retrieve remote model: %w", err)
	}

	rsp = replaceExternalPackages(rsp)

	if err := os.MkdirAll(filepath.Dir(modelPath), 0755); err != nil {
		return fmt.Errorf("failed to create dir: %w", err)
	}

	if err := os.WriteFile(modelPath, rsp, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func replaceExternalPackages(in []byte) []byte {
	// replace external packages
	in = bytes.ReplaceAll(in, []byte(`nullable.String`), []byte(`*string`))
	in = bytes.ReplaceAll(in, []byte(`nullable.Bool`), []byte(`*bool`))
	in = bytes.ReplaceAll(in, []byte(`nullable.Float64`), []byte(`*float64`))
	in = bytes.ReplaceAll(in, []byte(`nullable.Int `), []byte(`*int `))
	in = bytes.ReplaceAll(in, []byte(`nullable.Interface`), []byte(`any`))
	in = bytes.ReplaceAll(in, []byte(`nullable.HTTPHeader`), []byte(`*http.Header`))
	in = bytes.ReplaceAll(in, []byte(`nullable.TimeMicrosUnix`), []byte(`*time.Time`))
	// remove broken fields
	in = bytes.ReplaceAll(in, []byte(`_ struct{}`), []byte(`// _ struct{} // removed`))
	// add necessary imports
	in = bytes.ReplaceAll(in, []byte(`import (`), []byte("import (\n\t\"net/http\"\n\t\"time\""))
	// remove external unused imports
	in = bytes.ReplaceAll(in, []byte("\t\"github.com/elastic/apm-data/input/elasticapm/internal/modeldecoder/nullable\"\n"), []byte{})
	// export root structs
	in = bytes.ReplaceAll(in, []byte(`type errorRoot struct {`), []byte(`type ErrorRoot struct {`))
	in = bytes.ReplaceAll(in, []byte(`type metadataRoot struct {`), []byte(`type MetadataRoot struct {`))
	in = bytes.ReplaceAll(in, []byte(`type metricsetRoot struct {`), []byte(`type MetricsetRoot struct {`))
	in = bytes.ReplaceAll(in, []byte(`type spanRoot struct {`), []byte(`type SpanRoot struct {`))
	in = bytes.ReplaceAll(in, []byte(`type transactionRoot struct {`), []byte(`type TransactionRoot struct {`))
	in = bytes.ReplaceAll(in, []byte(`type logRoot struct {`), []byte(`type LogRoot struct {`))
	// add omitempty json tag
	in = bytes.ReplaceAll(in, []byte("\"`\n"), []byte(",omitempty\"`\n"))
	in = bytes.ReplaceAll(in, []byte("\" validate:\""), []byte(",omitempty\" validate:\""))
	return in
}

func okDo(u string) ([]byte, error) {
	rsp, err := http.Get(u)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non 200 status code: %s", rsp.Status)
	}

	b, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	return b, nil
}
