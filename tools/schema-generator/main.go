package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"

	"github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
	"github.com/iancoleman/orderedmap"
	"github.com/invopop/jsonschema"

	"github.com/nscuro/dtapac/internal/audit"
)

func main() {
	var outputDir string
	flag.StringVar(&outputDir, "output", ".", "Output directory")
	flag.Parse()

	reflector := &jsonschema.Reflector{
		AllowAdditionalProperties:  true,
		DoNotReference:             true,
		RequiredFromJSONSchemaTags: true,
		Mapper: func(r reflect.Type) *jsonschema.Schema {
			if r == reflect.TypeOf(uuid.UUID{}) {
				return &jsonschema.Schema{
					Type:   "string",
					Format: "uuid",
				}
			}

			// Avoid endless recursion: PolicyViolation -> PolicyCondition -> Policy -> PolicyConditions -> Policy...
			// See
			//  - https://pkg.go.dev/github.com/DependencyTrack/client-go#PolicyViolation
			//	- https://pkg.go.dev/github.com/DependencyTrack/client-go#PolicyCondition
			//  - https://pkg.go.dev/github.com/DependencyTrack/client-go#Policy
			if r == reflect.TypeOf(dtrack.Policy{}) || r == reflect.TypeOf(&dtrack.Policy{}) {
				properties := orderedmap.New()
				properties.Set("uuid", &jsonschema.Schema{
					Type:   "string",
					Format: "uuid",
				})
				properties.Set("name", &jsonschema.Schema{
					Type: "string",
				})
				properties.Set("operator", &jsonschema.Schema{
					Type: "string",
				})
				properties.Set("violationState", &jsonschema.Schema{
					Type: "string",
				})

				return &jsonschema.Schema{
					Type:       "object",
					Properties: properties,
				}
			}
			return nil
		},
	}

	log.Printf("generating finding input schema")
	err := writeSchema(reflector, &audit.Finding{}, filepath.Join(outputDir, "finding.schema.json"))
	if err != nil {
		log.Fatalf("failed to generate schema file for finding: %v", err)
	}

	log.Printf("generating violation input schema")
	err = writeSchema(reflector, &audit.Violation{}, filepath.Join(outputDir, "violation.schema.json"))
	if err != nil {
		log.Fatalf("failed to generate schema file for violation: %v", err)
	}
}

func writeSchema(reflector *jsonschema.Reflector, input any, filePath string) error {
	schema, err := reflector.Reflect(input).MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to generate schema: %w", err)
	}

	// The output is not formatted by jsonschema, so we're re-encoding it
	// with proper indentation.

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer file.Close()

	var decodedSchema map[string]any
	err = json.NewDecoder(bytes.NewReader(schema)).Decode(&decodedSchema)
	if err != nil {
		return fmt.Errorf("failed to decode json schema: %w", err)
	}

	// Reset file pointer, so we can write to it without re-opening
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to reset file pointer: %w", err)
	}

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")

	return enc.Encode(decodedSchema)
}
