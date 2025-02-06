const jwt = require('jsonwebtoken');
const logger = require("./Logger");
const prisma = require('./PrismaClient');
const { merge } = require('lodash');
const ApiError = require('./ApiError');
const { rateLimits } = require('./Utils');

const validateSchema = (schema) => async (req, res, next) => {
    try {
        req.body = await schema.parseAsync(req.body);
        next();
    }
    catch (err) {
        next({ path: `${req.originalUrl}/middleware/validate`, status: 422, message: err.errors[0].message, extraData: err.errors })
    }
}

const errorMiddleware = (err, req, res, next) => {
    console.error(err);
    let error = {
        message: err.message || 'Something went wrong',
    };
    if (err.extraData) {
        error = merge(error, { extraData: err.extraData });
    }
    if (!err.statusCode)
        err.statusCode = 400;
    // throw new ApiError(err.statusCode, err.message)
    res.status(err.statusCode).send(new ApiError(err.statusCode, err.message, error, err.stack));
}

const verifyJWT = async (req, res, next) => {
    const token = req.cookies?.token || req.header("Authorization")?.split(" ")[1];
    if (!token) {
        logger.warn(`[/middleware/verifyJWT] - token missing`);
        logger.debug(`[/middleware/verifyJWT] - token: ${token}`);
        return next({ path: "/middleware/verifyJWT", statusCode: 401, message: "No token provided" });
    }
    try {
        let payload;
        try {
            payload = await jwt.verify(token.toString(), process.env.JWT_SECRET);
        } catch (jwtError) {
            logger.warn(`[/middleware/verifyJWT] - invalid token`);
            logger.debug(`[/middleware/verifyJWT] - token: ${token}`);
            return next({ path: "/middleware/verifyJWT", statusCode: 401, message: "Invalid token" })
        }

        if (!payload.id) {
            logger.warn(`[/middleware/verifyJWT] - invalid token`);
            logger.debug(`[/middleware/verifyJWT] - token: ${token}`);
            return next({ path: "/middleware/verifyJWT", statusCode: 401, message: "Invalid token" })
        }
        const user = await prisma.users.findUnique({
            where: {
                sys_id: payload.id
            }
        });

        if (!user) {
            logger.warn(`[/middleware/verifyJWT] - user not found`);
            logger.debug(`[/middleware/verifyJWT] - user: ${payload.id}`);
            return next({ path: "/middleware/verifyJWT", statusCode: 401, message: "User not found" })
        }
        logger.info(`[/middleware/verifyJWT] - user: ${user.sys_id} authenticated`);
        req.user = user;
        next();
    } catch (error) {
        next({ path: "/middleware/verifyJWT", statusCode: 500, message: error.message, extraData: error })
    }
}

const isManufacturer = async (req, res, next) => {
    try {
        if (!req.user.role === "MANUFACTURER") {
            logger.warn(`[/middleware/isManufacturer] - manufacturer not found`);
            return res.status(400).json({
                error: "Manufacturer not found",
            });
        }
        logger.info(`[/middleware/isManufacturer] - manufacturer: ${req.user.sys_id} found`);
        next();
    } catch (error) {
        logger.error(`[/middleware/isManufacturer] - ${error.stack}`);
        next({ status: 400, message: error.message, extraData: error })
    }

}

const isUser = async (req, res, next) => {
    try {
        const { email } = req.body;
        let user = await prisma.users.findUnique({
            where: {
                email: email.toLowerCase(),
            },
        });
        if (!user) {
            logger.warn(`[/middleware/isUser] - user not found`);
            logger.debug(`[/middleware/isUser] - email: ${email}`);
            return res.status(400).json({
                error: "User not found",
            });
        }
        logger.info(`[/middleware/isUser] - user: ${user.sys_id} found`);
        req.user = user;
        next();
    } catch (error) {
        logger.error(`[/middleware/isUser] - ${error.stack}`);
        next({ status: 400, message: error.message, extraData: error })
    }
}

const isVerified = async (req, res, next) => {
    try {
        logger.debug(`[/middleware/isVerified] - user: ${req.user.sys_id}.`);
        if (req.user.isVerified === false) {
            logger.warn(`[/middleware/isVerified] - user: ${req.user.sys_id} is not verified`);
            return next({ path: "/middleware/isVerified", statusCode: 400, message: "User is not verified" })
        }
        logger.info(`[/middleware/isVerified] - user: ${req.user.sys_id} is not verified`);
        next();
    } catch (error) {
        next({ status: 500, message: error.message, extraData: error })
    }
}

const verificationMailSent = async (req, res, next) => {
    try {
        let tokenData = await prisma.verificationTokens.findUnique({
            where: {
                userId: req.user.sys_id,
            },
        });
        if (tokenData && tokenData.expiresAt > new Date()) {
            logger.warn(`[/middleWare/verificationMailSent] - verification mail already sent`);
            logger.debug(`[/middleWare/verificationMailSent] - email: ${req.user.email}`);
            const leftTime = new Date(Number(tokenData.expiresAt) - Date.now());
            return next({path: "/middleWare/verificationMailSent", statusCode: 400, message: `Verification mail already sent, you can resend it after ${leftTime.getMinutes() != 0 ? `${leftTime.getMinutes()}:${leftTime.getSeconds()} minutes` : `${leftTime.getSeconds()} seconds`}`})
        }
        next();
    } catch (error) {
        next({ status: 500, message: error.message, extraData: error })
    }
}

module.exports = {
    verifyJWT,
    isUser,
    isVerified,
    verificationMailSent,
    validateSchema,
    errorMiddleware,
    isManufacturer
}
