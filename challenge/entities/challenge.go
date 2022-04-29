package entities

type Challenge struct {
	Name string `json:"name"`
}

func (c Challenge) GetName() string {
	return c.Name
}
