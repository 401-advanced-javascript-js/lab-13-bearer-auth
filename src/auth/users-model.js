'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// CONFIGURATION VALUES
const TOKEN_LIFETIME = process.env.TOKEN_LIFETIME || '1m';
const SINGLE_USE_TOKEN = !!process.env.SINGLE_USE_TOKENS;
const SECRET = process.env.SECRET || 'foobar';

const usedTokens = new Set();
// ----------------------------------------------------------------------

const users = new mongoose.Schema({
  username: {type:String, required:true, unique:true},
  password: {type:String, required:true},
  email: {type: String},
});

users.pre('save', function(next) {
  bcrypt.hash(this.password, 10)
    .then(hashedPassword => {
      this.password = hashedPassword;
      next();
    })
    .catch(e => { throw new Error(e); });
});

users.statics.createFromOauth = function(email) {

  if(! email) { return Promise.reject('Validation Error'); }

  return this.findOne( {email} )
    .then(user => {
      if( !user ) { throw new Error('User Not Found'); }
      console.log('Welcome Back', user.username);
      return user;
    })
    .catch( error => {
      console.log('Creating new user');
      let username = email;
      let password = 'none';
      return this.create({username, password, email});
    });

};

users.statics.authenticateBasic = function(auth) {
  let query = { username: auth.username };
  return this.findOne(query)
    .then( user => user && user.comparePassword(auth.password) )
    .catch(error => {throw error;});
};

users.statics.authenticateToken = (token) => {
  // Single Use
  if (usedTokens.has(token)) {
    return Promise.reject('Invalid Token');
  }
  try {
    const parsedToken = jwt.verify(token, SECRET);

    if (SINGLE_USE_TOKEN && parsedToken.type !== 'key') {
      usedTokens.add(token);
    }
    // same as
    // (SINGLE_USE_TOKEN) && parsedToken.type !== 'key' && usedTokens.add(token);

    // query to verify token belongs to user in database
    let query = {_id: parsedToken.id};
    return this.findOne(query);

  } catch(e) {
    throw new Error('Invalid Token');
  }
};

users.methods.comparePassword = function(password) {
  return bcrypt.compare( password, this.password )
    .then( valid => valid ? this : null);
};

users.methods.generateToken = function(type) {
  let token = {
    id: this._id,
    type: type || 'user',
  };

  const options = {};

  if (type !== 'key' && !!TOKEN_LIFETIME) {
    options.expiresIn = TOKEN_LIFETIME;
  }
  
  return jwt.sign(token, SECRET, options);
};

users.methods.generateKey = function() {
  return this.generateToken('key');
};

module.exports = mongoose.model('users', users);
