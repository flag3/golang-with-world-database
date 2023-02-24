package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/srinathgs/mysqlstore"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type City struct {
  ID          int    `json:"id,omitempty"  db:"ID"`
  Name        string `json:"name,omitempty"  db:"Name"`
  CountryCode string `json:"countryCode,omitempty"  db:"CountryCode"`
  District    string `json:"district,omitempty"  db:"District"`
  Population  int    `json:"population,omitempty"  db:"Population"`
}

type Country struct {
  Code            string          `json:"code,omitempty"  db:"Code"`
  Name            string          `json:"name,omitempty"  db:"Name"`
  Continent       string          `json:"continent,omitempty"  db:"Continent"`
  Region          string          `json:"region,omitempty"  db:"Region"`
  SurfaceArea     float32         `json:"surfacearea,omitempty"  db:"SurfaceArea"`
  IndepYear       sql.NullInt16   `json:"indepyear"  db:"IndepYear"`
  Population      int             `json:"population"  db:"Population"`
  LifeExpectancy  sql.NullFloat64 `json:"lifeexpectancy"  db:"LifeExpectancy"`
  GNP             sql.NullFloat64 `json:"gnp"  db:"GNP"`
  GNPOld          sql.NullFloat64 `json:"gnpold"  db:"GNPOld"`
  LocalName       string          `json:"localname"  db:"LocalName"`
  GovernmentForm  string          `json:"governmentform"  db:"GovernmentForm"`
  HeadOfState     sql.NullString  `json:"headofstate"  db:"HeadOfState"`
  Capital         sql.NullInt32   `json:"capital"  db:"Capital"`
  Code2           string          `json:"code2"  db:"Code2"`
}

type Me struct {
  Username string `json:"username,omitempty" db:"username"`
}

var (
  db *sqlx.DB
)

func main() {
  _db, err := sqlx.Connect("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local", os.Getenv("DB_USERNAME"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOSTNAME"), os.Getenv("DB_PORT"), os.Getenv("DB_DATABASE")))
  if err != nil {
    log.Fatalf("Cannot Connect to Database: %s", err)
  }
  db = _db

  store, err := mysqlstore.NewMySQLStoreFromConnection(db.DB, "sessions", "/", 60*60*24*14, []byte("secret-token"))
  if err != nil {
    panic(err)
  }

  e := echo.New()
  e.Use(middleware.Logger())
  e.Use(session.Middleware(store))

  e.GET("/ping", func(c echo.Context) error {
    return c.String(http.StatusOK, "pong")
  })
  e.POST("/login", postLoginHandler)
  e.POST("/signup", postSignUpHandler)

  withLogin := e.Group("")
  withLogin.Use(checkLogin)
  withLogin.GET("/cities/:cityName", getCityInfoHandler)
  withLogin.GET("/countries", getAllCountryInfoHandler)
  withLogin.GET("/cities/:cityName", getCityInfoHandler)
  withLogin.GET("/whoami", getWhoAmIHandler)
  e.Start(":4000")
}

type LoginRequestBody struct {
  Username string `json:"username,omitempty" form:"username"`
  Password string `json:"password,omitempty" form:"password"`
}

type User struct {
  Username   string `json:"username,omitempty"  db:"Username"`
  HashedPass string `json:"-"  db:"HashedPass"`
}

func postSignUpHandler(c echo.Context) error {
  req := LoginRequestBody{}
  c.Bind(&req)

  // もう少し真面目にバリデーションするべき
  if req.Password == "" || req.Username == "" {
    // エラーは真面目に返すべき
    return c.String(http.StatusBadRequest, "項目が空です")
  }

  hashedPass, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
  if err != nil {
    return c.String(http.StatusInternalServerError, fmt.Sprintf("bcrypt generate error: %v", err))
  }

  // ユーザーの存在チェック
  var count int

  err = db.Get(&count, "SELECT COUNT(*) FROM users WHERE Username=?", req.Username)
  if err != nil {
    return c.String(http.StatusInternalServerError, fmt.Sprintf("db error: %v", err))
  }

  if count > 0 {
    return c.String(http.StatusConflict, "ユーザーが既に存在しています")
  }

  _, err = db.Exec("INSERT INTO users (Username, HashedPass) VALUES (?, ?)", req.Username, hashedPass)
  if err != nil {
    return c.String(http.StatusInternalServerError, fmt.Sprintf("db error: %v", err))
  }
  return c.NoContent(http.StatusCreated)
}

func postLoginHandler(c echo.Context) error {
  req := LoginRequestBody{}
  c.Bind(&req)

  user := User{}
  err := db.Get(&user, "SELECT * FROM users WHERE username=?", req.Username)
  if err != nil {
    return c.String(http.StatusInternalServerError, fmt.Sprintf("db error: %v", err))
  }

  err = bcrypt.CompareHashAndPassword([]byte(user.HashedPass), []byte(req.Password))
  if err != nil {
    if err == bcrypt.ErrMismatchedHashAndPassword {
      return c.NoContent(http.StatusForbidden)
    } else {
      return c.NoContent(http.StatusInternalServerError)
    }
  }

  sess, err := session.Get("sessions", c)
  if err != nil {
    fmt.Println(err)
    return c.String(http.StatusInternalServerError, "something wrong in getting session")
  }
  sess.Values["userName"] = req.Username
  sess.Save(c.Request(), c.Response())

  return c.NoContent(http.StatusOK)
}

func checkLogin(next echo.HandlerFunc) echo.HandlerFunc {
  return func(c echo.Context) error {
    sess, err := session.Get("sessions", c)
    if err != nil {
      fmt.Println(err)
      return c.String(http.StatusInternalServerError, "something wrong in getting session")
    }

    if sess.Values["userName"] == nil {
      return c.String(http.StatusForbidden, "please login")
    }
    c.Set("userName", sess.Values["userName"].(string))

    return next(c)
  }
}

func getWhoAmIHandler(c echo.Context) error {
  return c.JSON(http.StatusOK, Me{
    Username: c.Get("userName").(string), 
  })
}

func getCityInfoHandler(c echo.Context) error {
  cityName := c.Param("cityName")

  city := City{}
  db.Get(&city, "SELECT * FROM city WHERE Name=?", cityName)
  if city.Name == "" {
    return c.NoContent(http.StatusNotFound)
  }

  return c.JSON(http.StatusOK, city)
}

func getAllCountryInfoHandler(c echo.Context) error {
  const n = 239
  existsEmptyName := false
  country := [n]Country{}
  for i := 0; i < n; i++ {
    db.Get(&country[i], "SELECT * FROM country LIMIT ?, 1", i)
    if country[i].Name == "" {
      existsEmptyName = true
    }
  }
  if existsEmptyName == true {
    return c.NoContent(http.StatusNotFound)
  }

  return c.JSON(http.StatusOK, country)
}

func addCityHandler(c echo.Context) error {
  var data City
  cityState := "INSERT INTO city (Name, CountryCode, District, Population) VALUES (?, ?, ?, ?)"

  if err := c.Bind(&data); err != nil {
    return c.JSON(http.StatusBadRequest, data)
  }
  db.Exec(cityState, data.Name, data.CountryCode, data.District, data.Population)
  return c.JSON(http.StatusOK, data)
}
