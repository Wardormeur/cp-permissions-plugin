var seneca = require('seneca')({ transport: {
      type: 'web',
      web: {
        timeout: 120000,
        port: 10303
      }
    },
    strict: {add: false, result: false},
  })

seneca.use(require('../index'), {
  config: __dirname + '/math_conf',
  clients: ['math', 'display']
});

seneca.add({role: 'math', cmd: 'sum'}, function (msg, respond) {
  var sum = msg.left + msg.right
  seneca.act({role: 'math', cmd:'product', left: sum, right: sum}, function (err, response) {
    respond(null, {answer: response.product})
  });
})

seneca.add({role: 'math', cmd: 'product'}, function (msg, respond) {
  var product = msg.left * msg.right
  respond(null, { answer: product })
})


seneca.act({role: 'math', cmd: 'sum', left: 1, right: 2}, function (err, result){
  seneca.act({role: 'display', cmd: 'console', info: result});
})

seneca.listen()
.client({ type: 'web', port: 10304, pin: { role: 'display', cmd: '*' } })
