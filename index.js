var express = require("express");
var app = express();
const ejs = require("ejs");
const bodyParser = require("body-parser");
var crypto = require("crypto");
const md5 = require("md5");
const bcrypt = require("bcrypt");
// setting up the various modules
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static("public"));
// variables used
const port = 3000;
const algorithm = "aes-256-cbc";
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);
const saltRounds = 10;
// getting to the home route
app.get("/", (req, res) => {
  res.render("index");
});
// algorithm for encrypting the password
function encrypt(password, algoType) {
  switch (algoType) {
    case 1:
      // AES algo
      let cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(key), iv);
      let encrypted = cipher.update(password);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      return { iv: iv.toString("hex"), encryptedData: encrypted.toString("hex") };
    case 2:
      // Hashing algo
      let hash = md5(password);
      return hash;
    case 3:
      // Salting algo
      const salt = bcrypt.hashSync(password, saltRounds);
      return salt;
  }
}
app.get("/encrypt", (req, res) => {
  // get the text from the form
  var text = req.query.text;
  var password = req.query.password;
  var algoType = req.query.algo_chosen;
  // passing the text and password to the encypt function
  var crypted = encrypt(password, parseInt(algoType));
  // render the encrypted text
  if (algoType == 1) {
    // for AES
    res.render("encrypt", {
      text: text,
      password: password,
      crypted_text: crypted,
      algo_type: algoType,
      crypted_text: crypted.encryptedData
    });
  } else {
    // for hashing and salting
    res.render("encrypt", {
      text: text,
      password: password,
      crypted_text: crypted,
      algo_type: algoType,
      crypted_text: crypted
    });
  }
});
// function to decrypt the encrypted data
function decrypt(text) {
  let iv = Buffer.from(text.iv, "hex");
  let encryptedText = Buffer.from(text.encryptedData, "hex");
  let decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(key), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}
app.get("/decrypt", (req, res) => {
  // getting the variables
  var text = req.query.text;
  var password = req.query.password;
  var algoType = req.query.algo_type;
  // getting the objects through functions
  var crypted = encrypt(password, parseInt(algoType));
  var decrypted_text = decrypt(crypted);
  // rendering the decrypt.ejs file
  res.render("decrypt", {
    text: text,
    password: password,
    crypted_text: crypted.encryptedData,
    algo_type: algoType, 
    decrypted_text: decrypted_text
  });
});
// listening to the port
app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});