package models

type Users struct {
	ID           int `gorm:"primarykey"`
	Username     string
	Email        string
	Passwordhash string
}
type Admin struct {
	Username     string `gorm:"primarykey"`
	Email        string
	Passwordhash string
}
