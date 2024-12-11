import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt"

const db = new pg.Client({

  //cargar la base de datos
  user: "postgres",
  host: "localhost",
  database: "database",
  password: "password",
  port: 5432,
});

db.connect();

const app = express();
const port = 3000;
//para el algoritmo de encriptado
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));


//gets con templates estaticos (ejs)
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const pass = req.body.password;
  const mail = req.body.username;

  const checkExistence = await db.query("SELECT * FROM users WHERE email = $1", [mail]);

  if(checkExistence.rows.length > 0){
    res.send("EMAIL ALREADY EXISTS");
  }else{
    //hashing y encriptado
    bcrypt.hash(pass, saltRounds, async (err,hash) =>{
      if(err){
        console.log(err);
      }else{

        //actualizar a un orm para evitar inyeccion sql

          const result = await db.query("INSERT INTO users (email,password) VALUES ($1, $2);",[mail,hash]); 
          res.render("secrets.ejs");
      }
    });
    
  }

 
});

app.post("/login", async (req, res) => {
  const req_pass = req.body.password;
  const loginPass = req_pass;
  const mail = req.body.username;

  //comprobar si existe el mail (usar orm para evitar inyeccion sql)
  const checkExistence = await db.query("SELECT * FROM users WHERE email = $1", [mail]);

  if(checkExistence.rows.length > 0){
    const correct_password = checkExistence.rows[0].password;

    //comparar contraseña con el que hay en la base de datos
    bcrypt.compare(loginPass,correct_password, (err, result) =>{
      if(err){
        console.log(err);
      }else{
        if(result){
          res.render("secrets.ejs")

        }else{
          res.send("CONTRASEÑA INCORRECTA");
        }
      }
    });
  }else{
    res.send("NO EXISTE EL USUARIO");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
