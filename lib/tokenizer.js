var crypto = require('crypto');

module.exports = {
  createToken: function (token) {
    var hash = crypto.createHmac('sha512', process.env.PERM_MASTERKEY);
    hash.update(token);
    return hash.digest('hex');

  },
  isValid: function  (token, hash) {
    var valid = false;
    if (this.createToken(token) === hash){
        valid = true;
    }
    return valid;
  },


};
