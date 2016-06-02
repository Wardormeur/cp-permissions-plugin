module.exports = function () {
  return {
      roles: ['none', 'basic-user', 'cdf-admin'],
      userTypes: ['attendee-u13', 'attendee-o13', 'parent', 'mentor'],
      roleHierarchy: {
        'cdf-admin': {
          'basic-user': {
            'none': {}
          }
        }
      },
      userTypeHierarchy: {
        'basic-user': {
          'champion': [{
            'parent': [
              {'attendee-o13': {}},
              {'attendee-u13': {}}
              ]
            },
            {'mentor': {}}
            ]
          }
      },
    };

};
