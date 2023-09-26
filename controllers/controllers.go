package controllers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"main.go/models"
	verify "main.go/userverify"
	util "main.go/utilities"
)

func LoadSignup() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.HTML(http.StatusOK, "signup.html", gin.H{})
	}
}
func Signup(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")
		email := c.PostForm("email")

		var existingUserCount int64

		// Check if username exists
		db.Model(&models.Users{}).Where("username = ?", username).Count(&existingUserCount)
		if existingUserCount > 0 {
			c.HTML(http.StatusConflict, "signup.html", gin.H{"message": "username already exists"})
			return
		}
		// //check whether email already exists

		db.Model(&models.Users{}).Where("email=?", email).Count(&existingUserCount)
		if existingUserCount > 0 {
			c.HTML(http.StatusConflict, "signup.html", gin.H{"message": "email is already registered"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			c.HTML(http.StatusBadRequest, "signup.html", gin.H{"message": "error hashing password"})
			return
		}
		newuser := models.Users{Username: username, Email: email, Passwordhash: string(hash)}
		res := db.Create(&newuser)
		if res.Error != nil {
			c.HTML(http.StatusBadRequest, "signup.html", gin.H{"message": "error adding user"})
			return
		}
		//after completion of signup redirect to login page
		c.Redirect(http.StatusSeeOther, "/login")
	}
}
func Showloginpage() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	}
}

func Postlogin(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		email := c.PostForm("email")
		password := c.PostForm("password")
		admin, isadmin := verify.Verifyadmin(email, password, *db)
		if isadmin {
			token, err := util.GenerateJWT(admin.Username)
			if err != nil {
				c.HTML(http.StatusBadRequest, "login.html", gin.H{"message": err})
				return
			}
			c.SetCookie("token", token, int(time.Hour*24), "/", "localhost", false, true)
			c.Redirect(http.StatusSeeOther, "/admin")
			return
		}
		user, err := verify.Verifyuser(email, password, *db)
		if err != nil {
			c.HTML(http.StatusBadRequest, "login.html", gin.H{"message": err})
			return
		}
		token, err := util.GenerateJWT(user.Username)
		if err != nil {
			c.HTML(http.StatusBadRequest, "login.html", gin.H{"message": err})
			return
		}

		// Setting token as a cookie
		c.SetCookie("token", token, int(time.Hour*24), "/", "localhost", false, true)
		c.Redirect(http.StatusSeeOther, "/home")
	}
}

func Showhomepage() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the token from the cookie
		tokenCookie, err := c.Cookie("token")
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/login")
			return
		}

		// Verify the token and extract claims
		claims, err := util.VerifyJWT(tokenCookie)
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/login")
			return
		}

		// Pass the username to the template
		c.HTML(http.StatusOK, "home.html", gin.H{
			"Username": claims.Username,
		})
	}
}
func Logout() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.SetCookie("token", "", -1, "/", "localhost", false, true)
		c.Redirect(http.StatusSeeOther, "/login")
	}
}
