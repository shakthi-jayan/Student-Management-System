const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const mysql = require("mysql");
const flash = require("connect-flash");
const path = require("path");
const csv = require("fast-csv");
const fs = require("fs");
const app = express();

// Middleware setup
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(flash());
app.use(express.static(path.join(__dirname, "static")));
app.set('views', path.join(__dirname, 'templates'));

// Set the view engine
app.set("view engine", "ejs");

// MySQL Connection Function
function connectDB(user, password, database) {
  return mysql.createConnection({
    host: "localhost",
    user: user,
    password: password,
    database: database,
  });
}

// Routes

// Login Page
app.get("/", (req, res) => {
  res.render("authentication/login", { message: req.flash("error") });
});

app.post("/", (req, res) => {
  const { username, password } = req.body;
  if (
    ["user1", "user2", "user3", "user4"].includes(username) &&
    password === `password${username.slice(-1)}`
  ) {
    req.session.user = username;
    res.redirect(`/dashboard/database${username.slice(-1)}`);
  } else {
    req.flash("error", "Invalid login credentials");
    res.redirect("/");
  }
});

// Dashboard
app.get("/dashboard/:db", (req, res) => {
  const user = req.session.user;
  if (!user) return res.redirect("/");

  const db = req.params.db;
  const connection = connectDB(user, `password${user.slice(-1)}`, db);

  connection.connect((err) => {
    if (err) {
      req.flash("error", "Failed to connect to the database");
      return res.redirect("/");
    }

    connection.query("SELECT enroll_no, name, course FROM student_details", (error, results) => {
      if (error) {
        req.flash("error", "Failed to fetch data");
        return res.redirect("/");
      }

      res.render("application/user_dashboard", { db, user, students: results });
    });

    connection.end();
  });
});

// Add Student
app.post("/add/:db", (req, res) => {
  const user = req.session.user;
  if (!user) return res.redirect("/");

  const db = req.params.db;
  const connection = connectDB(user, `password${user.slice(-1)}`, db);
  const data = [
    req.body.enroll_no,
    req.body.course,
    req.body.sex,
    req.body.name,
    req.body.father_name,
    req.body.address1,
    req.body.address2,
    req.body.city,
    req.body.pincode,
    req.body.qualification,
    req.body.date_of_join,
    req.body.age,
    req.body.scheme,
    req.body.date_of_birth,
    req.body.concession,
    req.body.net_fees,
  ];

  connection.connect((err) => {
    if (err) {
      req.flash("error", "Failed to connect to the database");
      return res.redirect("/");
    }

    const query = `
      INSERT INTO student_details (enroll_no, course, sex, name, father_name, address1, address2, city, pincode,
      qualification, date_of_join, age, scheme, date_of_birth, concession, net_fees) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    connection.query(query, data, (error) => {
      if (error) {
        req.flash("error", "Failed to add student");
        return res.redirect(`/dashboard/${db}`);
      }

      req.flash("success", "Student added successfully");
      res.redirect(`/dashboard/${db}`);
    });

    connection.end();
  });
});

// Export Data
app.get("/export/:db/:table", (req, res) => {
  const user = req.session.user;
  if (!user) return res.redirect("/");

  const db = req.params.db;
  const table = req.params.table;
  const connection = connectDB(user, `password${user.slice(-1)}`, db);

  connection.connect((err) => {
    if (err) {
      req.flash("error", "Failed to connect to the database");
      return res.redirect(`/dashboard/${db}`);
    }

    connection.query(`SELECT * FROM ${table}`, (error, results, fields) => {
      if (error) {
        req.flash("error", "Failed to fetch data");
        return res.redirect(`/dashboard/${db}`);
      }

      const filePath = path.join(__dirname, `${table}.csv`);
      const writeStream = fs.createWriteStream(filePath);
      csv
        .write([fields.map((field) => field.name), ...results.map((row) => Object.values(row))], {
          headers: true,
        })
        .pipe(writeStream)
        .on("finish", () => {
          res.download(filePath, `${table}.csv`, () => {
            fs.unlinkSync(filePath); // Delete file after download
          });
        });
    });

    connection.end();
  });
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
