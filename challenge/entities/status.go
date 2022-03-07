package entities

type ChallengeStatus string

const (
	ChallengeStatusPassed  ChallengeStatus = "PASSED"
	ChallengeStatusFailed  ChallengeStatus = "FAILED"
	ChallengeStatusSkipped ChallengeStatus = "SKIPPED"
)
