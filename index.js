'use strict';

var _ = require('lodash');
var async = require('async');
var tokenizer = require('./lib/tokenizer');

module.exports = function (options) {
  var seneca = this;
  var plugin = 'cd-permissions';

  //  Required params
  var config = require(options.config)();
  var clients = options.clients;

  seneca.add({role: 'cd-permissions', cmd: 'check_permissions'},
    require('./lib/check_permissions').bind( _.extend(_.clone(this), {permConfig: config}) ));

  seneca.root.context = {};

  var wrapTokenization = function (done) {
    _.each(clients, function(lib){
      seneca.wrap({role: lib}, function(msg, respond){
        console.log('original', msg);
        if(_.isUndefined(msg.perm)){
          msg = getContext(msg);
          console.log('extended', msg);
        }
        this.prior(msg, respond);
      });
    });
    done();
  };


  var wrapLib = function (lib) {
    seneca.wrap({role: lib}, function(msg, respond){
      if(!msg.perm
        || (!msg.perm.token && !msg.perm.hash)
        || !tokenizer.isValid(msg.perm.token, msg.perm.hash)){
        console.log('need validation');
        seneca.act({role: 'cd-permissions', cmd: 'check_permissions', msg: msg},
          (function (err, response){
            if(response && !_.isObject(response)){
              // Doesn't this mean that every call used on permissions as a check is allowed to do anything? MegaCare here
              msg.perm = {};
              msg.perm.token = Date.now().toString();
              msg.perm.hash = tokenizer.createToken(msg.perm.token);
              setContext(msg);
              this.prior(msg, function(a, b) {
                //  TODO: Find a way to revoke this token without breaking the wrapping :(
                // console.log('respond', respond)
                // if(msg.transport$){
                //   console.log('token revoked');
                //   revokeToken(msg.id);
                // }
                return respond(a, b);
              });
            } else {
              respond(null, {http$: response});
            }
          }).bind(this)
        );
      } else {
        setContext(msg);
        this.prior(msg, respond);
      }
    });
  };

  var setContext = function(msg) {
    seneca.root.context[msg.id] = {token: msg.perm.token, hash: msg.perm.hash};
  };

  var getContext = function(msg) {
    return _.extend(msg, {perm: seneca.root.context[msg.id]});
  };

  var revokeToken = function(id) {
    delete seneca.root.context[id];
  };

  async.waterfall(
    [
    function(done){
      _.each(_.keys(config), wrapLib);
      done();
    },
    wrapTokenization,
  ]
  );

  return {
    name: plugin
  };
};
