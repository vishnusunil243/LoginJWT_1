package main

import (
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"main.go/controllers"
	"main.go/middleware"
	"main.go/models"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

var db *gorm.DB
var err error

func init() {

	//establishing connection to postgres
	err = godotenv.Load()
	if err != nil {
		log.Fatal("error loading .env file")
	}
	dsn := os.Getenv("DB_URL")
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		panic("error connecting to database")
	}
	db.AutoMigrate(&models.Users{})
	db.AutoMigrate(&models.Admin{})
}
func main() {
	router := gin.Default()

	//to load css files
	router.Static("/static", "static")

	//to load javascript files
	router.Static("/js", "js")

	//to load html files
	router.LoadHTMLGlob("templates/*.html")

	//home route
	router.GET("/home", middleware.Authenticate(), middleware.Clearcache(), controllers.Showhomepage())

	//logout route
	router.GET("/logout", controllers.Logout()).Use(middleware.Clearcache())

	//signup routes
	router.GET("/signup", middleware.Loginauthenticate(db), controllers.LoadSignup())
	router.POST("/signup", controllers.Signup(db))

	//login routes
	router.GET("/login", middleware.Loginauthenticate(db), controllers.Showloginpage())
	router.POST("/login", controllers.Postlogin(db))

	//admin panel routes
	adminGroup := router.Group("/admin")
	adminGroup.Use(middleware.Adminauthenticate(db))
	{
		// Route to display the admin panel
		adminGroup.GET("/", controllers.Showadminpanel(db))
		//to search users
		adminGroup.POST("/", controllers.Searchusers(db))

		// Route to add a user
		adminGroup.GET("/adduser", controllers.Showadduser())
		adminGroup.POST("/adduser", controllers.Adduser(db))

		// Route to delete a user by username
		adminGroup.POST("/delete-user/:username", controllers.Deleteuser(db))

		// Route to show the edit user page
		adminGroup.GET("/edit-user/:username", controllers.Showedituser(db))

		// Route to update a user by username
		adminGroup.POST("/edit-user/:username", controllers.Updateuser(db))

		//Route to add admins
		adminGroup.GET("/add-admin", controllers.Showaddadmin())
		adminGroup.POST("/add-admin", controllers.Addadmin(db))
	}

	router.Run(":8080")
}
