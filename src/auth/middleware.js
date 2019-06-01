'use strict';

/**
 * Auth Middleware
 * @module auth/middleware
 */

const User = require('./users-model.js');

module.exports = (req, res, next) => {
  
  try {
    let [authType, authString] = req.headers.authorization.split(/\s+/);
    
    switch( authType.toLowerCase() ) {
    case 'basic':
      return _authBasic(authString);
    case 'bearer':
      return _authBearer(authString);
    default:
      return _authError();
    }
  }
  catch(e) {
    _authError();
  }
  
  
  /**
   * Authenticates Basic Token
   * sends back error if authentication fails
   * 
   * @param {string} str
   */
  function _authBasic(str) {
    // str: am9objpqb2hubnk=
    let base64Buffer = Buffer.from(str, 'base64'); // <Buffer 01 02 ...>
    let bufferString = base64Buffer.toString();    // john:mysecret
    let [username, password] = bufferString.split(':'); // john='john'; mysecret='mysecret']
    let auth = {username,password}; // { username:'john', password:'mysecret' }
    
    return User.authenticateBasic(auth)
      .then(user => _authenticate(user) )
      .catch(_authError);
  }

  /**
   * Authenticates Bearer Token
   * sends back error if authentication fails
   * 
   * @param {string} token 
   */
  function _authBearer(token) {
    return User.authenticateToken(token)
      .then(user => _authenticate(user))
      .catch(_authError);
  } 

  /**
   * Authenticates User Object
   * sends back error if authentication fails
   * 
   * @param {Object} user 
   */
  function _authenticate(user) {
    if(user) {
      req.user = user;
      req.token = user.generateToken();
      next();
    }
    else {
      _authError();
    }
  }
  
  /**
   * Error handler
   */
  function _authError() {
    next('Invalid User ID/Password');
  }
};