package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"main.go/models"
	util "main.go/utilities"
)

func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenstring string

		// First, try to get the token from the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			// Token found in Authorization header
			tokenstring = authHeader
		} else {
			// Token not found in Authorization header, try to get it from cookies
			cookie, err := c.Request.Cookie("token")
			if err == nil {
				// Token found in cookies
				tokenstring = cookie.Value
			}
		}

		if tokenstring == "" {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}
		//verify the jwt token
		_, err := util.VerifyJWT(tokenstring)
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}

		c.Next()
	}
}
func Adminauthenticate(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenstring string

		// First, try to get the token from the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			// Token found in Authorization header
			tokenstring = authHeader
		} else {
			// Token not found in Authorization header, try to get it from cookies
			cookie, err := c.Request.Cookie("token")
			if err == nil {
				// Token found in cookies
				tokenstring = cookie.Value
			}
		}

		if tokenstring == "" {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}

		claims, err := util.VerifyJWT(tokenstring)
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}
		var admin models.Admin
		res := db.Where("username=?", claims.Username).First(&admin)
		if res.Error != nil {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}
		c.Next()
	}
}
func Clearcache() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.Next()
	}
}

func Loginauthenticate(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if the token cookie is present
		token, err := c.Cookie("token")
		if err != nil {
			c.Next()
			return
		}
		claims, err := util.VerifyJWT(token)
		if err != nil {
			c.Next()
			return
		}
		var admin models.Admin
		res := db.Where("username=?", claims.Username).First(&admin)
		if res.Error == nil {
			c.Redirect(http.StatusSeeOther, "/admin")
			c.Abort()
			return
		}

		if err == nil {
			// If the token cookie is present, redirect to the home page
			c.Redirect(http.StatusSeeOther, "/home")
			c.Abort() // Abort further processing
			return
		}

		// Continue to the next handler if the token cookie is not present
		c.Next()
	}
}
