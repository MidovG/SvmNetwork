package userModel

type User struct {
	Id              int
	Name            string
	Email           string
	Password        string
	Role            string
	CountOfBadWords int
}
