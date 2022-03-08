// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package model

type FlowResult struct {
	NextChallenges []string `json:"nextChallenges"`
}

type InitializeFlowResponse struct {
	Token      string   `json:"token"`
	Challenges []string `json:"challenges"`
}

type RequestOTPResult struct {
	Token      string   `json:"token"`
	Reference  string   `json:"reference"`
	Challenges []string `json:"challenges"`
}

type SolveOTPInput struct {
	Reference string `json:"reference"`
	Code      string `json:"code"`
}

type SolveOTPResult struct {
	Token      string      `json:"token"`
	FlowResult *FlowResult `json:"flowResult"`
	Challenges []string    `json:"challenges"`
}
