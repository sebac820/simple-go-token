package token

import "time"

type Nower interface {
	Now() time.Time
}

type DefaultNower struct{}

func (n DefaultNower) Now() time.Time {
	return time.Now()
}
