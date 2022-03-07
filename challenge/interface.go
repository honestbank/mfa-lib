package challenge

type IChallenge interface {
	Solve(body map[string]interface{}) (*map[string]interface{}, error)
	Request(body map[string]interface{}) (*map[string]interface{}, error) // Request a challenge, ex: for OTP you have to request an OTP before you can solve it
}
