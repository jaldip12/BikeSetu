const { PrismaClient } = require('@prisma/client'); // Assuming you have prisma client installed
const cookieParser = require('cookie-parser');
const cors = require('cors');
const express = require('express');
const helmet = require('helmet');
const http = require('http');
const morgan = require('morgan');
const routes = require('./router');
const { errorMiddleware } = require('./utils/Middleware');
const logger = require('./utils/Logger');

const prisma = new PrismaClient(); // Initialize prisma client

const app = express();
const server = http.createServer(app);


app.use(morgan("[:date[clf]] :method :url :status :res[content-length] - :response-time ms"));

app.use(cors({
  origin: [process.env.FRONTEND_URL],
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true
}));
app.use(express.json());
app.use(helmet());
app.use(cookieParser());
const port = process.env.PORT || 3000;

server.listen(port, () => {
  console.log(`Worker ${process.pid} is listening on port ${port}`);
  prisma.$connect().then(() => {
    console.log('Connected to database');
  })
  // Import and use routes from a separate file
  routes(app);
  app.use(errorMiddleware);
});

app.get("/", (req, res) => {
  res.json("OK");
})

process.on("unhandledRejection", (reason, p) => {
  logger.debug(
    `Unhandled Rejection at:  Promise ${p} reason: ${reason}`
  );
  // application specific logging, throwing an error, or other logic here
});
