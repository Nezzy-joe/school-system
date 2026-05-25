package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

//TOKEN :eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InNlY3VyZUB0ZXN0LmNvbSIsImV4cCI6MTc3NTU2OTIyOX0.m29ZfRUjZbADas6lQEPUlTwcLX6d45wbuGRzvelyUQE

// USER STRUCT

type User struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// LOGIN STRUCT
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}
type Student struct {
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	ClassID     int    `json:"class_id"`
	DateOfBirth string `json:"date_of_birth"`
	Gender      string `json:"gender"`
}

// Suject Struct
type Subject struct {
	Name    string `json:"name"`
	ClassID int    `json:"class_id"`
}

type Result struct {
	StudentID int    `json:"student_id"`
	SubjectID int    `json:"subject_id"`
	Score     int    `json:"score"`
	Term      string `json:"term"`
	Session   string `json:"session"`
}

// to be moved later
var jwtKey = []byte("my_secret_key")

var db *sql.DB

// MAIN FUNCTION

func main() {
	connStr := "user=nezzy password=strongpassword dbname=school_system sslmode=disable"

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/register", registerUser)
	http.HandleFunc("/users", authMiddleware(getUsers))
	//http.HandleFunc("/students", authMiddleware(createStudent))
	http.HandleFunc("/students", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			createStudent(w, r)
		} else if r.Method == "GET" {
			getStudents(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

	}))

	// SUBJECT ROUTE
	http.HandleFunc("/subjects", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			createSubject(w, r)
		} else if r.Method == "GET" {
			getSubjects(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	http.HandleFunc("/login", loginUser)

	//RESULT ROUTE
	http.HandleFunc("/results", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			createResult(w, r)
		} else if r.Method == "GET" {
			getResults(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	log.Println("Server running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

//REGISTER USERS

func registerUser(w http.ResponseWriter, r *http.Request) {

	var user User

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	query := `
	
	INSERT INTO users (name, email, password_hash, role)
	VALUES ($1, $2, $3, $4)

	`
	//HASH PASSWORD
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(query, user.Name, user.Email, string(hashedPassword), user.Role)
	if err != nil {
		log.Println("DB Error", err)

		if strings.Contains(err.Error(), "duplicate key") {
			http.Error(w, "Email already exists", http.StatusBadRequest)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Write([]byte("User registered successfully"))
}

//GET USERS

func getUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, email, role FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []map[string]interface{}

	for rows.Next() {
		var id int
		var name, email, role string

		err := rows.Scan(&id, &name, &email, &role)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		user := map[string]interface{}{
			"id":    id,
			"name":  name,
			"email": email,
			"role":  role,
		}
		users = append(users, user)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// LOGIN FUNCTION
func loginUser(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var storedHash string

	err = db.QueryRow("SELECT password_hash FROM users WHERE email=$1", req.Email).Scan(&storedHash)
	if err != nil {
		http.Error(w, "INVALID email or password", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.Password))
	if err != nil {
		http.Error(w, "INVALID email or password", http.StatusUnauthorized)
		return
	}
	//w.Write([]byte("Login Successful!"))

	expirationTime := time.Now().Add(1 * time.Hour)

	claims := &Claims{
		Email: req.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Println("JWT ERROR:", err)
		http.Error(w, "Could not generate token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})

}

// MIDDLEWARE
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// STUDENT CREATE HANDLER
func createStudent(w http.ResponseWriter, r *http.Request) {
	var student Student

	err := json.NewDecoder(r.Body).Decode(&student)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	query := `
		INSERT INTO students (first_name, last_name, class_id, date_of_birth, gender)
		
		VALUES ($1, $2, $3, $4, $5)

	`
	_, err = db.Exec(query,
		student.FirstName,
		student.LastName,
		student.ClassID,
		student.DateOfBirth,
		student.Gender,
	)

	if err != nil {
		log.Println("DB Error:", err)
		http.Error(w, "Could not create Student", http.StatusInternalServerError)
		return
	}
	w.Write([]byte("Student created successfully"))

}

// GetStudent function
func getStudents(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
	SELECT s.id, s.first_name, s.last_name, s.date_of_birth, s.gender, c.name
	FROM students s
	JOIN classes c ON s.class_id = c.id
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var students []map[string]interface{}

	for rows.Next() {
		var id int
		var firstName, lastName, dob, gender, className string

		err := rows.Scan(&id, &firstName, &lastName, &dob, &gender, &className)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		students = append(students, map[string]interface{}{
			"id":            id,
			"first_name":    firstName,
			"last_name":     lastName,
			"date_of_birth": dob,
			"gender":        gender,
			"class":         className,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(students)
}

// Subject Handler
func createSubject(w http.ResponseWriter, r *http.Request) {
	var subject Subject

	err := json.NewDecoder(r.Body).Decode(&subject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	query := `
	INSERT INTO subjects (name, class_id)
	VALUES ($1, $2)

	`
	_, err = db.Exec(query, subject.Name, subject.ClassID)
	if err != nil {
		log.Println("DB Error:", err)
		http.Error(w, "Could not create subject", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Subject created successfully"))

}

// GetSubject dunction
func getSubjects(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
	SELECT sub.id, sub.name, c.name
	FROM subjects sub
	JOIN classes c ON sub.class_id = c.id
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var subjects []map[string]interface{}

	for rows.Next() {
		var id int
		var subjectName, className string

		err := rows.Scan(&id, &subjectName, &className)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		subjects = append(subjects, map[string]interface{}{
			"id":    id,
			"name":  subjectName,
			"class": className,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(subjects)
}

// FUNCTION CREATE RESULTS
func createResult(w http.ResponseWriter, r *http.Request) {
	var result Result

	err := json.NewDecoder(r.Body).Decode(&result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if result.Score < 0 || result.Score > 100 {
		http.Error(w, "Score must be between 0 and 100", http.StatusBadRequest)
		return
	}

	query := `
	
	INSERT INTO results (student_id, subject_id, score, term, session)
	VALUES ($1, $2, $3, $4, $5)
	`
	_, err = db.Exec(query,

		result.StudentID,
		result.SubjectID,
		result.Score,
		result.Term,
		result.Session,
	)
	/*if err != nil {
		log.Println("DB Error:", err)
		http.Error(w, "Could not create result", http.StatusInternalServerError)
		return
	}
	w.Write([]byte("Result created successfully"))*/

	if err != nil {
		log.Println("DB Error:", err)

		if strings.Contains(err.Error(), "duplicate key") {
			http.Error(w, "Result already exists for this student, subject, term, and session", http.StatusBadRequest)
			return
		}

		http.Error(w, "Could not create result", http.StatusInternalServerError)
		return
	}
}

// FUNCTION GET RESULT

func getResults(w http.ResponseWriter, r *http.Request) {

	rows, err := db.Query(`
	
		SELECT
		r.id,
		s.first_name,
		s.last_name,
		sub.name,
		r.score,
		r.term,
		r.session
		FROM results r
		JOIN students s ON r.student_id = s.id
		JOIN subjects sub ON r.subject_id = sub.id
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int
		var firstName, lastName, subjectName, term, session string
		var score int

		err := rows.Scan(&id, &firstName, &lastName, &subjectName, &score, &term, &session)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		grade := calculateGrade(score)

		results = append(results, map[string]interface{}{
			"id":      id,
			"student": firstName + " " + lastName,
			"subject": subjectName,
			"score":   score,
			"grade":   grade,
			"term":    term,
			"session": session,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
func calculateGrade(score int) string {
	if score >= 70 {
		return "A"
	} else if score >= 60 {
		return "B"
	} else if score >= 50 {
		return "C"
	} else if score >= 45 {
		return "D"
	} else if score >= 40 {
		return "E"
	}
	return "F"
}
