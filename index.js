'use strict';

var _ = require('lodash');
var async = require('async');
var tokenizer = require('./lib/tokenizer');

module.exports = function (options) {
  var seneca = this;
  var plugin = 'cd-permissions';

  //  Required params
  var config = require(options.config)();

  var addValidator = function (lib) {
    var perms = {permConfig: {}};
    perms.permConfig[lib] = config[lib];
    seneca.add({role: lib, cmd: 'check_permissions'},
    require('./lib/check_permissions').bind( _.extend(_.clone(seneca), perms) ));
  };

  _.each(_.keys(config), addValidator);


  return {
    name: plugin
  };
};
