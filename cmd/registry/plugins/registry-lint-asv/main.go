// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"path"
	"strings"
	"regexp"
	//"reflect"

	lint "github.com/apigee/registry/cmd/registry/plugins/linter"
	"github.com/apigee/registry/pkg/application/style"
)

// spectralConfiguration describes a spectral ruleset that is used to lint
// a given API Spec.
type spectralConfiguration struct {
	Extends [][]string      `json:"extends"`
	Rules   map[string]bool `json:"rules"`
}

// spectralLintResult contains metadata related to a rule violation.
type spectralLintResult struct {
	Code     string            `json:"code"`
	Path     []string          `json:"path"`
	Message  string            `json:"message"`
	Severity int32             `json:"severity"`
	Source   string            `json:"source"`
}

// spectralLintRange is the start and end location for a rule violation.
/* type spectralLintRange struct {
	Start spectralLintLocation `json:"start"`
	End   spectralLintLocation `json:"end"`
}

// spectralLintLocation is the location in a file for a rule violation.
type spectralLintLocation struct {
	Line      int32 `json:"line"`
	Character int32 `json:"character"`
} */

// Runs the spectral linter with a provided spec and configuration path
type runLinter func(specPath, configPath string) ([]*spectralLintResult, error)

// spectralLinterRunner implements the LinterRunner interface for the Spectral linter.
type spectralLinterRunner struct{}

func (linter *spectralLinterRunner) Run(req *style.LinterRequest) (*style.LinterResponse, error) {
	return linter.RunImpl(req, runSpectralLinter)
}

func (linter *spectralLinterRunner) RunImpl(
	req *style.LinterRequest,
	runLinter runLinter,
) (*style.LinterResponse, error) {
	lintFiles := make([]*style.LintFile, 0)

	// Create a temporary directory to store the configuration.
	root, err := os.MkdirTemp("", "spectral-config-")
	if err != nil {
		return nil, err
	}

	// Defer the deletion of the temporary directory.
	defer os.RemoveAll(root)

	// Create configuration file for Spectral to execute the correct rules
	configPath, err := linter.createConfigurationFile(root, req.GetRuleIds())
	if err != nil {
		return nil, err
	}

	// Traverse the files in the directory
	err = filepath.Walk(req.GetSpecDirectory(), func(filepath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Execute the spectral linter.
		if(path.Ext(info.Name()) == ".yaml") {
			lintResults, err := runLinter(filepath, configPath)
			if err != nil {
				return err
			}
			lintProblems := getLintProblemsFromSpectralResults(lintResults)
	
			// Formulate the response.
			lintFile := &style.LintFile{
				FilePath: filepath,
				Problems: lintProblems,
			}
			lintFiles = append(lintFiles, lintFile)
		}

		// Get the lint results as a LintFile object from the spectral output file

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &style.LinterResponse{
		Lint: &style.Lint{
			Name:  "registry-lint-asv",
			Files: lintFiles,
		},
	}, nil
}

func (linter *spectralLinterRunner) createConfigurationFile(root string, ruleIds []string) (string, error) {
	// Create the spectral configuration.
	configuration := spectralConfiguration{}
	configuration.Rules = make(map[string]bool)
	if len(ruleIds) == 0 {
		// if no rules were specified, use the default rules.
		configuration.Extends = [][]string{{"spectral:oas", "all"}, {"spectral:asyncapi", "all"}}
	} else {
		configuration.Extends = [][]string{{"spectral:oas", "off"}, {"spectral:asyncapi", "off"}}
	}
	for _, ruleName := range ruleIds {
		configuration.Rules[ruleName] = true
	}
	// Marshal the configuration into a file.
	file, err := json.MarshalIndent(configuration, "", " ")
	if err != nil {
		return "", err
	}
	// Write the configuration to the temporary directory.
	configPath := filepath.Join(root, "spectral.json")
	err = os.WriteFile(configPath, file, 0644)
	if err != nil {
		return "", err
	}
	return configPath, nil
}

func getLintProblemsFromSpectralResults(
	lintResults []*spectralLintResult,
) []*style.LintProblem {
	problems := make([]*style.LintProblem, len(lintResults))
	for i, result := range lintResults {
		problem := &style.LintProblem{
			Message:    result.Message,
			RuleId:     result.Code,
			RuleDocUri: "https://meta.stoplight.io/docs/spectral/docs/reference/openapi-rules.md#" + result.Code,
		}
		problems[i] = problem
	}
	return problems
}

func findOutputFile(rootDir string, pattern string) ([]string, error) {
	regex, err := regexp.Compile(pattern)
    if err != nil {
        return nil, err
    }
	//var fileName []string
	fileName := []string{}
	err = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
            return err
        }
		if regex.MatchString(info.Name()) {
            // Read the contents of the matching file
            fileName = append(fileName, path)

            // Process the file content as needed
        }
		return nil
	})
	if err != nil {
        return nil, err
    }

    return fileName, nil
}


func runSpectralLinter(specPath, configPath string) ([]*spectralLintResult, error) {
	// Create a temporary destination directory to store the output.
	root, err := os.MkdirTemp("", "asv-output-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)

	outputPath := filepath.Join(root, "asv-lint.json")

	// Set the destination path of the spectral output.
	//outputPath := filepath.Join(root, "spectral-lint.json")

	//pattern := ".*string=([^ ]*)"
	//exp := regexp.MustCompile(`.*string=([^ ]*)`)
	//dirPath := exp.FindStringSubmatch(specPath)
	cmd := exec.Command("asv",
		"validate", specPath)

	output, err := cmd.CombinedOutput()
	currentDir, err := os.Getwd()
	filePattern := `^validation_report.*\.json`
	fileName, err := findOutputFile(currentDir, filePattern)
	lintOutput := []spectralLintResult{}
	var resultObj spectralLintResult
	outPath, err := os.ReadFile(fileName[len(fileName) - 1])
	if err != nil {
		return nil, err
	}
	var jsonData map[string]interface{}
	err = json.Unmarshal(outPath, &jsonData)
	if err != nil {
		//fmt.Println("Error:", err)
		return nil, err
	}
	resultsArray, ok := jsonData["result"]
	if !ok {
		//fmt.Println("No 'result' key found in the JSON.")
		return nil, err
	}
	// Convert the "results" value to a slice of interfaces
	results, ok := resultsArray.([]interface{})
	if !ok {
		//fmt.Println("Invalid format for 'result' key in the JSON.")
		return nil, err
	}
	resultMap, ok := results[0].(map[string]interface{})
	nestedResults, ok := resultMap["results"]
	// Print the nested "results" value
	nestedResultsArray, ok := nestedResults.([]interface{})
	//fmt.Println("Nested 'results' value at index", nestedResults)
	for _, singleRule := range nestedResultsArray {
		singleRuleMap := singleRule.(map[string]interface{})
		singleRuleResults := singleRuleMap["results"]
		path := singleRuleMap["categoryName"].(string)
		//iterate over the results for each category
		singleRuleResultArray := singleRuleResults.([]interface{})
		for _, eachRule := range singleRuleResultArray {
			eachRuleMap := eachRule.(map[string]interface{})
			status:= eachRuleMap["status"]
			if status == nil {
				groupRuleResults := eachRuleMap["results"]
				groupRuleResultArray := groupRuleResults.([]interface{})
				for _, eachRuleGroup := range groupRuleResultArray {
					eachRuleGroupMap := eachRuleGroup.(map[string]interface{})
					status := eachRuleGroupMap["status"]
					if status != "PASS" {
						code := eachRuleGroupMap["ruleCode"]
						error:= eachRuleGroupMap["errors"]
						warning:= eachRuleGroupMap["warnings"]
						severity := int(0)
						if warning == nil && error == nil {
							continue
						}
						if len(warning.([]interface{})) > 0 {
							severity = int(2)
						} else if len(error.([]interface{})) > 0 {
							severity = int(1)
						}
						resultObj = spectralLintResult{
							Code: code.(string),
							Path: []string{path},
							Source: "/tmp/registry-spec-1506160066/openapi.yaml",
							Severity: int32(severity),
							Message: eachRuleGroupMap["ruleName"].(string),
						}
						lintOutput = append(lintOutput, resultObj)		
					}
				}
			}
			if status != "PASS" {
				code := eachRuleMap["ruleCode"]
				error:= eachRuleMap["errors"]
				warning:= eachRuleMap["warnings"]
				severity := int(0)
				if warning == nil && error == nil {
					continue
				}
				if len(warning.([]interface{})) > 0 {
					severity = int(2)
				} else if len(error.([]interface{})) > 0 {
					severity = int(1)
				}
				resultObj = spectralLintResult{
					Code: code.(string),
					Path: []string{path},
					Source: "/tmp/registry-spec-1506160066/openapi.yaml",
					Severity: int32(severity),
					Message: eachRuleMap["ruleName"].(string),
				}
				lintOutput = append(lintOutput, resultObj)
			}
	
		}
	}
	file, err := os.Create(outputPath)
	if err != nil {
		//fmt.Println("Error opening file:", err)
		return nil, err
	}
	//defer file.Close()
	Data, err:= json.MarshalIndent(lintOutput, "", " ")
   	if err != nil {
       	//fmt.Println("Error:", err)
    	return nil, err
    }
	_, err = file.Write(Data)
	if err != nil {
		//fmt.Println("Error writing to file:", err)
		return nil, err
	}

	if err != nil {
		switch v := err.(type) {
			case *exec.ExitError:
				code := v.ExitCode()
				if code == 1 {
					// This just means the linter found errors
				} else {
					log.Printf("linter error %T (%s)", err, specPath)
					log.Printf("%s", string(output))
				}
			case *exec.Error:
				if strings.Contains(v.Err.Error(), "executable file not found") {
					return nil, v.Err
				}
				log.Printf("linter error %T (%s)", err, specPath)
				log.Printf("%s", string(output))
			default:
				log.Printf("linter error %T (%s)", err, specPath)
				log.Printf("%s", string(output))
		}
	}

	// Read and parse the spectral output.
/* text:= string(output)
pattern := `Overall Result: (.+)`

    // Compile the regular expression pattern
    regex := regexp.MustCompile(pattern)

    // Find the first match in the input string
    match := regex.FindStringSubmatch(text)
	result := match[1]
	log.Printf(match[1]) */

	
	
	b, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, err
	}
	var lintResults []*spectralLintResult
	err = json.Unmarshal(b, &lintResults)
	if err != nil {
		return nil, err
	}

	return lintResults, nil
}

func main() {
	lint.Main(&spectralLinterRunner{})
}
