var seneca = require('seneca')({ transport: {
      type: 'web',
      web: {
        timeout: 120000,
        port: 10303
      }
    },
    strict: {add: false, result: false}
  })

seneca.use(require('../index'), {
  config: __dirname + '/math_conf',
  clients: ['math', 'display']
});

seneca.add({role: 'math', cmd: 'sum'}, function (args, done) {
  var sum = args.left + args.right
  seneca.act({role: 'math', cmd:'product', left: sum, right: sum}, function (err, response) {
    if(err) return done(err);
    done(null, {answer: response.answer})
  });
})

seneca.add({role: 'math', cmd: 'product'}, function (args, done) {
  var product = args.left * args.right
  done(null, { answer: product });
})


seneca.act({role: 'math', cmd: 'sum', left: 1, right: 2}, function (err, result){
  if(err) console.log('err', err);
  seneca.act({role: 'display', cmd: 'console', info: result});
})

seneca.listen()
.client({ type: 'web', port: 10304, pin: { role: 'display', cmd: '*' } })
