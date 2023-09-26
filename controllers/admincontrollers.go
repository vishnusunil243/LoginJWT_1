package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"main.go/models"
	util "main.go/utilities"
)

func Showadminpanel(db *gorm.DB) gin.HandlerFunc {
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
		var users []models.Users
		res := db.Order("username").Find(&users)

		if res.Error != nil {
			c.HTML(http.StatusBadRequest, "admin_panel.html", gin.H{"message": "Error displaying all users"})
			return
		}

		c.HTML(http.StatusOK, "admin_panel.html", gin.H{"Users": users, "admin": claims.Username})
	}
}

func Deleteuser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		//retrieve username
		username := c.Param("username")

		//find retrieved user information from database
		res := db.Where("username=?", username).Delete(&models.Users{})
		if res.Error != nil {
			c.HTML(http.StatusBadRequest, "admin_panel.html", gin.H{"message": "error deleting user"})
			return
		}
		//redirect to admin route
		c.Redirect(http.StatusSeeOther, "/admin")

	}
}
func Showedituser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Retrieve the username from the URL parameters
		username := c.Param("username")

		//retrieve the user data from database
		var retrievedUser models.Users
		res := db.Where("username=?", username).Find(&retrievedUser)
		if res.Error != nil {
			c.Redirect(http.StatusSeeOther, "/admin")
			return
		}
		//load update.html with the users previous deails
		c.HTML(http.StatusOK, "update.html", gin.H{
			"User": retrievedUser, // Pass the retrieved user data to the template
		})
	}
}
func Showadduser() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.HTML(http.StatusOK, "adduser.html", nil)
	}
}
func Adduser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")
		email := c.PostForm("email")

		//check whether username already exists

		var existingUserCount int64

		// Check if username exists
		db.Model(&models.Users{}).Where("username = ?", username).Count(&existingUserCount)
		if existingUserCount > 0 {
			c.HTML(http.StatusConflict, "adduser.html", gin.H{"message": "username already exists"})
			return
		}
		//check whether email already exists

		db.Model(&models.Users{}).Where("email=?", email).Count(&existingUserCount)
		if existingUserCount > 0 {
			c.HTML(http.StatusConflict, "adduser.html", gin.H{"message": "email is already registered"})
			return
		}
		//hash the password
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			c.HTML(http.StatusBadRequest, "adduser.html", gin.H{"message": "error hashing password"})
			return
		}
		//for adding new user :
		newuser := models.Users{Username: username, Email: email, Passwordhash: string(hash)}
		res := db.Create(&newuser)
		if res.Error != nil {
			c.HTML(http.StatusBadRequest, "adduser.html", gin.H{"message": "error adding user"})
			return
		}
		c.Redirect(http.StatusSeeOther, "/admin")
	}
}
func Updateuser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		oldUsername := c.Param("username")
		newUsername := c.PostForm("username")
		newEmail := c.PostForm("email")
		newPassword := c.PostForm("password")

		// Retrieve the existing user
		var existingUser models.Users
		result := db.Where("username = ?", oldUsername).First(&existingUser)
		if result.Error != nil {
			c.HTML(http.StatusNotFound, "update.html", gin.H{"message": "User not found"})
			return
		}

		// Check if the new username is already taken
		var userWithNewUsername models.Users
		db.Where("username = ?", newUsername).Not("username IN (?)", existingUser.Username).First(&userWithNewUsername)
		if userWithNewUsername.Username != "" {
			c.HTML(http.StatusBadRequest, "update.html", gin.H{"message": "Username is already taken"})
			return
		}

		// Update the user's information
		existingUser.Username = newUsername
		existingUser.Email = newEmail

		// Hash the password if a new password is provided
		if newPassword != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			if err != nil {
				c.HTML(http.StatusBadRequest, "update.html", gin.H{"message": "Error hashing password"})
				return
			}
			existingUser.Passwordhash = string(hash)
		}

		// Save the updated user to the database
		db.Save(&existingUser)

		// Redirect or respond accordingly
		c.Redirect(http.StatusSeeOther, "/admin") // Redirect to admin page after update
	}
}

func Showaddadmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.HTML(http.StatusOK, "addadmin.html", nil)

	}
}

func Addadmin(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		adminname := c.PostForm("username")
		adminemail := c.PostForm("email")
		adminpassword := c.PostForm("password")
		var existingUserCount int64

		// Check if username exists
		db.Model(&models.Admin{}).Where("username = ?", adminname).Count(&existingUserCount)
		if existingUserCount > 0 {
			c.HTML(http.StatusConflict, "addadmin.html", gin.H{"message": "admin already exists"})
			return
		}
		//check if email is registered already
		db.Model(&models.Admin{}).Where("email = ?", adminemail).Count(&existingUserCount)
		if existingUserCount > 0 {
			c.HTML(http.StatusConflict, "addadmin.html", gin.H{"message": "admin  already exists"})
			return
		}
		//hash the password
		hash, err := bcrypt.GenerateFromPassword([]byte(adminpassword), bcrypt.DefaultCost)
		if err != nil {
			c.HTML(http.StatusBadRequest, "addadmin.html", gin.H{"message": "error hashing password"})
			c.Abort()
			return
		}
		//add new admin
		newadmin := models.Admin{Username: adminname, Email: adminemail, Passwordhash: string(hash)}
		res := db.Create(&newadmin)
		if res.Error != nil {
			c.HTML(http.StatusBadRequest, "addadmin.html", gin.H{"message": "error adding user"})
			return
		}
		c.Redirect(http.StatusSeeOther, "/admin")

	}
}

func Searchusers(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var searchusers []models.Users
		username := c.PostForm("search")
		//for searching using like query
		likeUser := "%" + username + "%"
		//to display user list in post:
		var users []models.Users
		res := db.Order("username").Find(&users)

		if res.Error != nil {
			c.HTML(http.StatusBadRequest, "admin_panel.html", gin.H{"message": res.Error})
		}
		// search using  LIKE query
		if err := db.Where("username ILIKE ?", likeUser).Find(&searchusers).Error; err != nil {
			c.HTML(http.StatusInternalServerError, "admin_panel.html.html", gin.H{"error": "Internal Server Error"})
			return
		}

		if len(users) == 0 {
			// No users found
			c.HTML(http.StatusOK, "admin_panel.html", gin.H{"error": "No users found"})
			return
		}

		// Users found, render the response with the user data
		c.HTML(http.StatusOK, "admin_panel.html", gin.H{"searchusers": searchusers, "Users": users})
	}
}
