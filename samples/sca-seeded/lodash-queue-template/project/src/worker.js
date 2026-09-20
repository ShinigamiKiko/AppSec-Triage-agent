const amqp = require('amqplib');
const _ = require('lodash');

async function main() {
  const connection = await amqp.connect(process.env.AMQP_URL);
  const channel = await connection.createChannel();
  await channel.consume('render-jobs', (msg) => {
    const job = JSON.parse(msg.content.toString());
    const render = _.template('Report for <%= data.title %>', { variable: job.variable });
    console.log(render({ title: job.title }));
    channel.ack(msg);
  });
}

main();
