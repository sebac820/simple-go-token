package token

// Token is a struct representation of a parsed JWT.
type Token struct {
	Audience string
	Subject  string
}
