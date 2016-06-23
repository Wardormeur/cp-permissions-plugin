var crypto = require('crypto');

/**
 * UNUSED LIB
 * Role was to create an auth token, may be used later on
 */
module.exports = {
  createHash: function (token) {
    var hash = crypto.createHmac('sha512', process.env.PERM_MASTERKEY);
    hash.update(token);
    return hash.digest('hex');

  },
  isValid: function  (token, hash) {
    var valid = false;
    if (this.createHash(token) === hash){
        valid = true;
    }
    return valid;
  },


};
