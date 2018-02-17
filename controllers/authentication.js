const jwt = require('jwt-simple');
const User = require('../models/user');
const secret = require('../config/secret');
const bcrypt = require('bcrypt-nodejs');
const models = require('../models');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, secret);
}

exports.signin = function(req, res, next) {
  // User has already had their email and password auth'd
  // We just need to give them a token
  res.send({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
  const email = req.body.email;
  var password = req.body.password;

  if (!email || !password) {
    return res.status(422).send({ error: 'You must provide email and password'});
  }

  // See if a user with the given email exists
  models.user.findOne({
    where:{
      email: email  
    }
  }).then(existingUser=>{
    
    console.log('existingUser',existingUser);
    
    // If a user with email does exist, return an error
    if (existingUser) {
      return res.status(422).send({ error: 'Email is in use' });
    }
    

    // If a user with email does NOT exist, create and save user record
    
    // generate a salt then run callback
    bcrypt.genSalt(10, function(err, salt) {
      if (err) { return next(err); }
    
      // hash (encrypt) our password using the salt
      bcrypt.hash(password, salt, null, function(err, hash) {
        if (err) { return next(err); }
        console.log('hash',hash);

        // overwrite plain text password with encrypted password
        password = hash;
        
        models.user.create({
          email:email,
          password:password
        })
        .then(user=>{
          res.json({token : tokenForUser(user)})
        })
        .catch(err=>{
          next(err)
        })
      })
    });
    
    
    
  })  
}