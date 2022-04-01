package entities

type MFAError struct {
	Code    string
	Message string
}

func (e MFAError) Error() string {
	return e.Message
}
