const express = require('express');
const _ = require('lodash');

const app = express();
app.use(express.json());

app.post('/greeting', (req, res) => {
  const render = _.template('Hello <%= data.name %>!', { variable: req.body.variable });
  res.send(render({ name: 'guest' }));
});

app.listen(3000);
