package experiment

import (
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"
)

// LoadAll reads every *.yaml file in dir, parses it into an ExperimentSpec,
// and validates required fields. Order is determined by os.ReadDir (alphabetical).
func LoadAll(dir string) ([]ExperimentSpec, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading experiment directory %q: %w", dir, err)
	}

	var specs []ExperimentSpec
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}

		var spec ExperimentSpec
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}

		if err := validate(spec); err != nil {
			return nil, fmt.Errorf("experiment %s failed validation: %w", entry.Name(), err)
		}

		specs = append(specs, spec)
	}
	return specs, nil
}

// validate checks that required fields are present and that expected_outcome
// is one of the two accepted values.
func validate(s ExperimentSpec) error {
	switch {
	case s.Name == "":
		return fmt.Errorf("field 'name' is required")
	case s.Image == "":
		return fmt.Errorf("field 'image' is required")
	case len(s.Command) == 0:
		return fmt.Errorf("field 'command' must have at least one element")
	case s.ExpectedOutcome == "":
		return fmt.Errorf("field 'expected_outcome' is required")
	case s.ExpectedOutcome != "blocked" && s.ExpectedOutcome != "permitted":
		return fmt.Errorf("field 'expected_outcome' must be \"blocked\" or \"permitted\", got %q", s.ExpectedOutcome)
	case s.Namespace == "":
		return fmt.Errorf("field 'namespace' is required")
	}
	return nil
}
