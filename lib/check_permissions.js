var async = require('async');
var _ = require('lodash');

/**
 * [checkPermissions description]
 * Format of a permission {
 * role: {'basic-user':{match: false}}
 * permissions: []
 * customValidator: functionName
 *}
 *
 * @param  {[type]}   args [description]
 * @param  {Function} done [description]
 * @return {[type]}        [description]
 */

function checkPermissions (args, cb) {
  var seneca = this;
  var plugin = args.role;
  var permissions = require('../config/permissions.js')();
  console.log(seneca.permConfig);
  var user = {};
  var cmd = args.msg.cmd;
  // Could be assigned while wrapping by binding a "rules context"
  var origin = args.msg.role;
  var rules = seneca.permConfig[origin];
  console.log('rules', rules, origin);
  var validity = false; //Global validity, if at least one rule is considered valid
  var httpErr = {};

  function getProfilesByActName (waterfallCb) {
    var profiles = {};
    if(rules[cmd]) profiles = rules[cmd];
    waterfallCb(null, profiles);
  }

  //  TODO : error msg with multiple profiles
  function checkProfiles(profiles, waterfallCb) {
    if(_.isEmpty(profiles)){
      cb(null, true);
    }else{
      async.some(profiles, checkValidity, function(valid){
        console.log('validity', valid, validity || valid, httpErr);
        cb(null, validity || valid ? true: httpErr);
      });

    }
  }

  /**
   * Check different parameters based upon a profile rule to ensure the actual user is allowed to use it
   * The validity is global to every check, while the error is passed as callback of every check
   * @param  {Object} profile    Instance of an act profile containing minimal status to use this act
   */
  function checkValidity(profile, validityCb) {
    var actions = [];
    var allowed = true; // This is a local validity to each rule/profile

    if(profile.role) actions.push(isRoleAllowed);
    if(profile.extendedUserTypes) actions.push(getAssociatedUserTypes);
    if(profile.userType) actions.push(isUserTypeAllowed);
    // if(profile.permissions) actions.push(isHavingPermissions);
    if(profile.customValidator) actions.push(applyCustomValidator);

    user = args.msg.user ? args.msg.user : {roles: ['none']} ;
    console.log('actions', actions);
    async.waterfall(actions, function(err, validities){
      return validityCb(allowed);
    });

    /**
     * Check if the profile role is matching (or lower) than the caller
     * @return {Object}      [description]
     */
    function isRoleAllowed (done) {
      httpErr = {
        status: 403
      };
      var profileDepth = getRoleDepth(permissions.roleHierarchy, profile.role);
      var userRoleDepth = getHighestPrivilegedRole(permissions.roleHierarchy, user.roles);
       console.log('depthsRole', permissions.roleHierarchy, profileDepth, user.roles, userRoleDepth);
      if (profileDepth >= userRoleDepth.value) {
        allowed = allowed && true;
        httpErr = null;
      }else {
        allowed = false;
      }
      return done(httpErr);
    }

    function isUserTypeAllowed (done) {
      httpErr = {
        status: 403
      };
      var profileDepth = getRoleDepth(permissions.userTypeHierarchy, profile.userType);
      var initType = JSON.parse(user.initUserType);
      if( initType.name ){
        user.initUserType = [initType.name];
      }
      var userRoleDepth = getHighestPrivilegedRole(permissions.userTypeHierarchy, _.toArray(user.initUserType));
      console.log('depthsUserType', profileDepth,
        _.toArray(user.initUserType), 'higher:', getHighestPrivilegedRole(permissions.userTypeHierarchy,
        _.toArray(user.initUserType)), userRoleDepth);

      if (profileDepth >= userRoleDepth.value) {
        allowed = allowed && true;
        httpErr = null;
      }else {
        allowed = false;
      }
      return done(httpErr);
    }

    function getAssociatedUserTypes (done) {
      seneca.act({role: 'cd-dojos', cmd: 'load_usersdojos', query: { userId: user.id }},
        function(err, associations){
          var userTypes = [];
          userTypes.push(JSON.parse(user.initUserType).name);
          _.map(associations, function(association) {
            _.map(association.userTypes, function(userType) {
              userTypes.push(userType);
            });
          });
          user.userType = userTypes;
          return done(err);
      });
    }

    /**
     * Call a seneca act based upon the msg saved as a config
     * Params are provided by the original call
     * ex : {role: 'cd-dojos', cmd: 'isDojoAdmin'}
     */
    function applyCustomValidator (done) {
      var customValidator = profile.customValidator;
      var httpErr = {
        status: 401
      };
      var omittedFields = [ 'cmd', 'role', 'ungate$', 'transport$', 'tx$', 'default$', 'meta$', 'plugin$', 'fatal$' ];
      async.every(customValidator, function(validatorAct, validatorCb) {
        seneca.act(_.defaults(validatorAct, _.omit(_.clone(args.msg), omittedFields)), function(err, response){
          return validatorCb(response);
        });
      }, function(valid){
        if (valid) {
          allowed = valid && true;
          httpErr = null;
        }else {
          allowed = false;
        }
        done(httpErr);
      });

    }

  }

  /**
   * Flatten a tree of roles to find the value until a maxDepth
   *  As much as possible, avoid recursivness with Js
   * @param  {Object} tree   one of permissions' userTypeHierarchy or roleHierarchy
   * @param  {String} value  one of those tree values
   * @return {Integer}       the depth
   */
  function getRoleDepth(tree, value){
    var found = false;
    var maxDepth = 5;
    var depth = -1;
    var localTree = _.clone(tree);
    do{
      var picked = localTree[value];
      depth += 1;
      if(!_.isUndefined(picked)){
        found = true;
      }
      //  Flatten our object (lodash doesn't support flattening of object, only arrays)
      var tempTree = {};
      _.each(_.keys(localTree), function(key) {
         _.merge(tempTree, localTree[key]);
      });
      localTree = tempTree ;

    }while(!found && depth < maxDepth);
    return depth;
  }


  /**
   * Search for the highest possible value in a tree when multiple options are possible
   * (ex multiple userTypes)
   * @param  {Object} tree   from permissions.js, userTypeHierarchy or roleHierarchy
   * @param  {Array} values  haystack for the highest one
   * @return {String}        one of the userType/Role without the actual index
   */
  function getHighestPrivilegedRole(tree, values){
    var lowerDepth = values[0];
    var indexes = {};
    lowerDepth = _.minBy(values, function(value){
      indexes[value] = getRoleDepth(tree, value);
      return indexes[value];
    });
    return {name: lowerDepth,
            value: indexes[lowerDepth]};
  }

  async.waterfall([
    getProfilesByActName,
    checkProfiles
  ]);

}

module.exports = checkPermissions;
