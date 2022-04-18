package entities

type MFAError struct {
	Code     string
	Message  string
	Metadata interface{}
}

func (e MFAError) Error() string {
	return e.Message
}
