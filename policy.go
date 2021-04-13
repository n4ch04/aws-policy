// Package policy provides a custom function to unmarshal AWS policies.
package policy

import (
	"encoding/json"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog/log"
)

// Policy represents an AWS iam policy document
type Policy struct {
	Version    string      `json:"Version"`
	ID         string      `json:"ID,omitempty"`
	Statements []Statement `json:"Statement"`
}

//Statement represents body of AWS iam policy document
type Statement struct {
	StatementID  string              `json:"StatementID,omitempty"`  // Statement ID, service specific
	Effect       string              `json:"Effect"`                 // Allow or Deny
	Principal    map[string][]string `json:"Principal,omitempty"`    // principal that is allowed or denied
	NotPrincipal map[string][]string `json:"NotPrincipal,omitempty"` // exception to a list of principals
	Action       []string            `json:"Action"`                 // allowed or denied action
	NotAction    []string            `json:"NotAction,omitempty"`    // matches everything except
	Resource     []string            `json:"Resource,omitempty"`     // object or objects that the statement covers
	NotResource  []string            `json:"NotResource,omitempty"`  // matches everything except
	Condition    []string            `json:"Condition,omitempty"`    // conditions for when a policy is in effect
}

// UnmarshalJSON decodifies input JSON info to Policy type
func (policyJSON *Policy) UnmarshalJSON(b []byte) error {

	var raw interface{}
	var err error
	var sSlice []Statement

	err = json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}
	// Parsing content of JSON element as empty interface
	switch value := raw.(type) {
	// All elelements
	case map[string]interface{}:
		for key, val := range value {
			switch key {
			case "Version":
				policyJSON.Version = val.(string)
			case "ID":
				policyJSON.ID = val.(string)
			case "Statement":
				sSlice = make([]Statement, 0)
				// Statement level - slice -> []interface{} , single element  -> map[string]interface
				switch statement := val.(type) {
				// Statement slice -> iterate over elements, parse and store into slice
				case []interface{}:
					//statement slice
					// iterate over statements
					for _, v := range statement {
						s := Statement{}
						// Type assertion to format info
						m := v.(map[string]interface{})
						// Parse statement
						s.Parse(m)
						// Append statement to slice
						sSlice = append(sSlice, s)
					}
				// Single statement -> parse and store it into slice
				case map[string]interface{}:
					s := Statement{}
					// Parse statement
					s.Parse(statement)
					sSlice = append(sSlice, s)
				}
				//Assign statements slice to Policy
				policyJSON.Statements = sSlice
			}
		}
	}
	return err
}

//Parse decodifies input json info into Statement type
func (s *Statement) Parse(statement map[string]interface{}) {

	//Definitions
	var principal, notPrincipal, action, notAction, resource, notResource, condition []string
	var err error
	// Iterate over map elements, each key element (ke) is the statement element identifer and each value element (ve) the statement element value
	for ke, ve := range statement {
		// Swtich case over key type (identifying Statement elements)
		switch ke {
		case "StatementID":
			// Type assertion to assign
			s.StatementID = ve.(string)
		case "Effect":
			//Type assertion to assign
			s.Effect = ve.(string)
		case "Principal":
			// principal(ve) can be map[string][]string/string -> needs processing
			// Initialize map
			s.Principal = make(map[string][]string)
			// procesing map
			me := ve.(map[string]interface{})
			// iterate over key principal (kp) and value principal (vp)
			for kp, vp := range me {
				// Vp can be string or []string
				switch vp := vp.(type) {
				case string:
					// As map each element is identified with a key and has a value
					principal = make([]string, 0)
					s.Principal[kp] = append(principal, vp)
				case []interface{}:
					// If value is an interface we know we have an []string -> knowing final type we can use mapstructure (which uses reflect) to store as final type
					err = mapstructure.Decode(ve, &s.Principal)
					if err != nil {
						log.Error().Str("Error parsing policies", "Error using mapstructure parsing Policy statement principal element").Err(err).Msg("")
					}
				}
			}
		case "NotPrincipal":
			// Same case as principal
			// notprincipal has to be ve = map[string][]string/string -> needs processing
			// Same procedure as Principal
			// Intialize map
			s.NotPrincipal = make(map[string][]string)
			// procesing map (ve)
			me := ve.(map[string]interface{})
			for knp, vnp := range me {
				// Vnp can be string or []string
				switch vnp := vnp.(type) {
				case string:
					notPrincipal = make([]string, 0)
					s.NotPrincipal[knp] = append(notPrincipal, vnp)
				case []interface{}:
					err = mapstructure.Decode(ve, &s.NotPrincipal)
					if err != nil {
						log.Error().Str("Error parsing policies", "Error using mapstructure parsing Policy statement not principal element").Err(err).Msg("")
					}
				}
			}
		case "Action":
			// We only have now string or []string, process with type assertion and mapstructure
			// Action can be string or []string
			switch ve := ve.(type) {
			case string:
				action = make([]string, 0)
				s.Action = append(action, ve)
			case []interface{}:
				err = mapstructure.Decode(ve, &s.Action)
				if err != nil {
					log.Error().Str("Error parsing policies", "Error using mapstructure parsing Policy statement action element").Err(err).Msg("")
				}
			}
		case "NotAction":
			// Same as Action
			// NotAction can be string or []string
			switch ve := ve.(type) {
			case string:
				notAction = make([]string, 0)
				s.NotAction = append(notAction, ve)
			case []interface{}:
				err = mapstructure.Decode(ve, &s.NotAction)
				if err != nil {
					log.Error().Str("Error parsing policies", "Error using mapstructure parsing Policy statement not action element").Err(err).Msg("")
				}
			}
		case "Resource":
			// Same as Action
			// Resource can be string or []string
			switch ve := ve.(type) {
			case string:
				resource = make([]string, 0)
				s.Resource = append(resource, ve)
			case []interface{}:
				err = mapstructure.Decode(ve, &s.Resource)
				if err != nil {
					log.Error().Str("Error parsing policies", "Error using mapstructure parsing Policy statement resource element").Err(err).Msg("")
				}
			}
		case "NotResource":
			// Same as Action
			// NotResource can be string or []string
			switch ve := ve.(type) {
			case string:
				notResource = make([]string, 0)
				s.NotResource = append(notResource, ve)
			case []interface{}:
				err = mapstructure.Decode(ve, &s.NotResource)
				if err != nil {
					log.Error().Str("Error parsing policies", "Error using mapstructure parsing Policy statement not resource element").Err(err).Msg("")
				}
			}
		case "Condition":
			// Condition can be string, []string or map(lot of options)
			switch ve := ve.(type) {
			case string:
				condition = make([]string, 0)
				s.Condition = append(condition, ve)
			case []interface{}:
				err = mapstructure.Decode(ve, &s.Condition)
				if err != nil {
					log.Error().Str("Error parsing policies", "Error using mapstructure parsing Policy statement condition element").Err(err).Msg("")
				}
			// If map format as raw text and store it as string
			case map[string]interface{}:
				condition = make([]string, 0)
				s.Condition = append(condition, fmt.Sprintf("%v", ve))
			}
		}
	}
}
