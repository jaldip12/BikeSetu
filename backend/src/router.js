const authRouter = require('./api/auth/index');
const usersRouter = require('./api/users/index');
const manufacturerRouter = require('./api/manufacturer/index');
const bikesRouter = require('./api/bikes/index');
const franchiseeRouter = require('./api/franchisee/index');
const bikesetuYardRouter = require('./api/bikesetu_yard/index');

function routes(app) {
    app.use('/auth', authRouter);
    app.use('/users', usersRouter);
    app.use('/manufacturer', manufacturerRouter);
    app.use('/bikes', bikesRouter);
    app.use('/franchisee', franchiseeRouter);
    app.use('/yard', bikesetuYardRouter);
}

module.exports = routes;
