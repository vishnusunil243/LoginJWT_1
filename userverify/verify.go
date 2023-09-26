package verify

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"main.go/models"
)

func Verifyuser(email, password string, db gorm.DB) (*models.Users, error) {
	var user models.Users
	res := db.Where("email=?", email).First(&user)
	if res.Error != nil {
		return nil, errors.New("user not found")
	}
	err := bcrypt.CompareHashAndPassword([]byte(user.Passwordhash), []byte(password))
	if err != nil {
		return nil, errors.New("invalid password")
	}
	return &user, nil
}

func Verifyadmin(email, password string, db gorm.DB) (*models.Admin, bool) {
	var admin models.Admin
	res := db.Where("email=?", email).First(&admin)
	if res.Error != nil {
		return nil, false
	}
	err := bcrypt.CompareHashAndPassword([]byte(admin.Passwordhash), []byte(password))
	if err != nil {
		return nil, false
	}
	return &admin, true
}
