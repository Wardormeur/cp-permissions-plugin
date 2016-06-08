var seneca = require('seneca')({ transport: {
      type: 'web',
      web: {
        timeout: 120000,
        port: 10304
      }
    },
    strict: {add: false, result: false},
  })

seneca.use(require('../index'), {
  config: __dirname + '/display_conf',
  clients: ['display']
});

seneca.add({role: 'display', cmd: 'console'}, function (msg, respond) {
  console.log(msg.info);
  respond()
})

seneca.listen()
