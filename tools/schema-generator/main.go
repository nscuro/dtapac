package main

import (
	"flag"
	"fmt"
	"github.com/google/uuid"
	"github.com/iancoleman/orderedmap"
	"github.com/invopop/jsonschema"
	"github.com/nscuro/dtapac/internal/audit"
	"github.com/nscuro/dtrack-client"
	"log"
	"os"
	"path/filepath"
	"reflect"
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
			//  - https://pkg.go.dev/github.com/nscuro/dtrack-client#PolicyViolation
			//	- https://pkg.go.dev/github.com/nscuro/dtrack-client#PolicyCondition
			//  - https://pkg.go.dev/github.com/nscuro/dtrack-client#Policy
			if r == reflect.TypeOf(&dtrack.Policy{}) {
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

	err := writeSchema(reflector, &audit.Finding{}, filepath.Join(outputDir, "finding.schema.json"))
	if err != nil {
		log.Fatalf("failed to generate schema file for finding: %v", err)
	}

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

	return os.WriteFile(filePath, schema, 0600)
}
