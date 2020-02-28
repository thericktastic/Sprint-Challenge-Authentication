const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const Users = require("../users/users-model.js");

const { jwtSecret } = require("../config/secrets.js");

router.post("/register", (req, res) => {
  // implement registration
  let user = req.body;

  const hash = bcrypt.hashSync(user.password, 8);

  user.password = hash;

  Users.add(user)
    .then(savedUser => {
      res.status(201).json(savedUser);
    })
    .catch(error => {
      console.log("This is error in router.post(register): ", error);
      res.status(500).json({ error: "Error registering" });
    });
});

router.post("/login", (req, res) => {
  // implement login
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = createToken(user);

        res.status(200).json({
          message: `Welcome to Camelot, ${user.username}!`,
          token
        });
      } else {
        res.status(401).json({ error: "Invalid credentials" });
      }
    })
    .catch(error => {
      console.log("This is error in router.post(login): ", error);
      res.status(500).json({ error: "Error logging in" });
    });
});

function createToken(user) {
  const payload = {
    userId: user.id
  };

  const options = {
    expiresIn: "4h"
  };

  return jwt.sign(payload, jwtSecret, options);
}

module.exports = router;
