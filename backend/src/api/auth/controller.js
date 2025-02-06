const prisma = require('../../utils/PrismaClient');
const logger = require('../../utils/Logger');
const bcrypt = require('bcrypt');
const crypto = require("crypto");
const mailer = require('../../utils/Mailer');
const jwt = require('jsonwebtoken');
const path = require('path');
const { default: axios } = require('axios');

const register = async (req, res, next) => {
    try {
        const { email, password, firstName, lastName, username } = req.body;
        const user = await prisma.users.findUnique({
            where: {
                email: email.toLowerCase(),
            },
        });
        if (user) {
            logger.warn(`[/auth/register] - email already exists`);
            logger.debug(`[/auth/register] - email: ${email}`);
            return next({ path: '/auth/register', statusCode: 400, message: "Email already exists" })
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        try {
            await prisma.$transaction(async (_prisma) => {
                const newUser = await _prisma.users.create({
                    data: {
                        firstName,
                        lastName,
                        username: email.split("@")[0],
                        email: email.toLowerCase(),
                        password: hashedPassword,
                        isPasswordSet: true
                    },
                });

                logger.info(`[/auth/register] - success - ${newUser.sys_id}`);
                logger.debug(`[/auth/register] - email: ${email}`);

                // send verification email with link
                const token = crypto.randomBytes(20).toString("hex");
                const verificationToken = await _prisma.verificationTokens.create({
                    data: {
                        userId: newUser.sys_id,
                        token,
                        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours from now
                    },
                });
                const verificationLink = `${process.env.FRONTEND_URL}/verify/${verificationToken.token}`;
                await mailer.sendVerificationLink(newUser.email, verificationLink);

                // send jwt token
                // const jwtToken = jwt.sign({ id: newUser.sys_id }, process.env.JWT_SECRET, {
                //     expiresIn: "7d",
                // });

                delete newUser.password;
                delete newUser.sys_id;

                return res.status(200).json({
                    // token: jwtToken,
                    user: newUser,
                    message: "User created successfully",
                });
            }, { timeout: 10000 });
        } catch (transactionError) {
            return next({ path: '/auth/register', statusCode: 400, message: transactionError.message, extraData: transactionError });
        }
    } catch (err) {
        next({ path: '/auth/register', statusCode: 400, message: err.message, extraData: err });
    }
}

/**
 * 
 * @param {*} req 
 * @param {import('express').Response} res 
 * @param {*} next 
 * @returns 
 */
const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        let user = await prisma.users.findUnique({
            where: {
                email: email.toLowerCase(),
            },
        });
        if (!user) {
            logger.warn(`[/auth/login] - email not found`);
            logger.debug(`[/auth/login] - email: ${email}`);
            return res.status(400).json({
                message: "Email not found",
            });
        }
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            logger.warn(`[/auth/login] - invalid password`);
            logger.debug(`[/auth/login] - email: ${email}`);
            return next({ path: '/auth/login', status: 400, message: "Invalid password" })
        }
        const token = jwt.sign({ id: user.sys_id }, process.env.JWT_SECRET, {
            expiresIn: "7d",
        });
        logger.info(`[/auth/login] - success - ${user.sys_id}`);
        logger.debug(`[/auth/login] - email: ${email}`);

        // Remove sensitive data from user object
        delete user.password;
        delete user.sys_id;
        delete user.token;

        return res.cookie("token", token).status(200).json({
            token,
            user,
        });
    } catch (err) {
        next({ path: '/auth/login', statusCode: 400, message: err.message, extraData: err });
    }
}

const verify = async (req, res, next) => {
    try {
        const { token } = req.params;
        const verificationToken = await prisma.verificationTokens.findUnique({
            where: {
                token,
            },
        });

        if (!verificationToken) {
            logger.warn(`[/auth/verify] - token not found`);
            logger.debug(`[/auth/verify] - token: ${token}`);
            return next({ path: '/auth/verify', status: 400, message: "Invalid token" })
        }
        // match the token
        if (verificationToken.token !== token) {
            logger.warn(`[/auth/verify] - token mismatch`);
            logger.debug(`[/auth/verify] - token: ${token}`);
            return next({ path: '/auth/verify', status: 400, message: "Invalid token" })
        }
        if (verificationToken.expiration < new Date()) {
            logger.warn(`[/auth/verify] - token expired`);
            logger.debug(`[/auth/verify] - token: ${token}`);
            return next({ path: '/auth/verify', status: 400, message: "Token expired" })
        }
        const user = await prisma.users.update({
            where: {
                sys_id: verificationToken.userId,
            },
            data: {
                isVerified: true,
            },
        });
        if (!user) {
            logger.error(`[/auth/verify] - user not found`);
            logger.debug(`[/auth/verify] - token: ${token}`);
            return next({ path: '/auth/verify', status: 400, message: "User not found" })
        }
        // delete verification token
        await prisma.verificationTokens.delete({
            where: {
                token,
            },
        });
        logger.info(`[/auth/verify] - success - ${user.sys_id}`);
        logger.debug(`[/auth/verify] - id: ${user.sys_id}`);
        return res.status(200).json({
            message: "Email verified successfully",
        });
    } catch (err) {
        console.log(err)
        next({ path: '/auth/verify', status: 400, message: err.message, extraData: err });
    }
}

const changePassword = async (req, res, next) => {
    try {
        const { newPassword, oldPassword } = req.body;
        const user = req.user;
        if (user.isPasswordSet === true) {
            const validPassword = await bcrypt.compare(oldPassword, user.password);
            if (!validPassword) {
                logger.warn(`[/auth/changePassword] - invalid password`);
                logger.debug(`[/auth/changePassword] - email: ${user.email}`);
                return next({ path: '/auth/changePassword', status: 400, message: "Invalid password" })
            }
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        await prisma.users.update({
            where: {
                sys_id: user.sys_id,
            },
            data: {
                password: hashedPassword,
                isPasswordSet: true
            },
        });
        logger.info(`[/auth/changePassword] - success - ${user.sys_id}`);
        logger.debug(`[/auth/changePassword] - email: ${user.email}`);
        return res.status(200).json({
            message: "Password changed successfully",
        });
    } catch (err) {
        next({ path: '/auth/changePassword', status: 400, message: err.message, extraData: err });
    }
}

const sendVerificationMail = async (req, res, next) => {
    try {
        const user = req.user;

        if (user.isVerified) {
            logger.warn(`[/auth/sendVerificationMail] - email already verified`);
            logger.debug(`[/auth/sendVerificationMail] - email: ${req.user.email}`);
            return next({ path: '/auth/sendVerificationMail', status: 400, message: "Email already verified" })
        }
        const token = crypto.randomBytes(20).toString("hex");
        const verificationToken = await prisma.verificationTokens.create({
            data: {
                userId: user.sys_id,
                token,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours from now
            },
        });
        const verificationLink = `${process.env.FRONTEND_URL}/verify/${verificationToken.token}`;
        await mailer.sendVerificationLink(user.email, verificationLink);
        logger.info(`[/auth/sendVerificationMail] - success - ${user.sys_id}`);
        logger.debug(`[/auth/sendVerificationMail] - email: ${user.email}`);
        return res.status(200).json({
            message: "Verification email sent successfully",
        });
    } catch (err) {
        next({ path: '/auth/sendVerificationMail', status: 400, message: err.message, extraData: err });
    }
}

const getUser = async (req, res, next) => {
    try {
        const user = req.user;
        if (!user) {
            logger.warn(`[/auth/getUser] - user not found`);
            logger.debug(`[/auth/getUser] - user: ${req.user.sys_id}`);
            return next({ path: '/auth/getUser', status: 400, message: "User not found" })
        }
        logger.info(`[/auth/getUser] - success - ${user.sys_id}`);
        logger.debug(`[/auth/getUser] - user: ${user.sys_id}`);
        delete user.password;
        delete user.sys_id;
        return res.status(200).json({
            user,
        });
    } catch (err) {
        next({ path: '/auth/getUser', status: 400, message: err.message, extraData: err });
    }
}

const logout = async (req, res, next) => {
    try {
        res.clearCookie('token');
        return res.status(200).json({
            message: "Logged out successfully"
        });
    } catch (err) {
        next({ path: '/auth/logout', status: 400, message: err.message, extraData: err });
    }
}

const continueWithGoogle = async (req, res) => {
    const {role} = req.params;
    const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${process.env.GOOGLE_REDIRECT_URI}&response_type=code&scope=profile email`;
    res.redirect(url);
}

const googleCallBack = async (req, res, next) => {
    const { code } = req.query;
    const {role}=req.params;

    try {
        // Exchange authorization code for access token
        const { data } = await axios.post('https://oauth2.googleapis.com/token', {
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            code,
            redirect_uri: process.env.GOOGLE_REDIRECT_URI,
            grant_type: 'authorization_code',
        });

        const { access_token, id_token } = data;

        // Use access_token or id_token to fetch user profile
        const { data: profile } = await axios.get('https://www.googleapis.com/oauth2/v1/userinfo', {
            headers: { Authorization: `Bearer ${access_token}` },
        });

        // Check if user exists in the database
        let user = await prisma.users.findUnique({
            where: {
                email: profile.email.toLowerCase(),
            },
        });
        if (!user) {
            // If user doesn't exist, create a new one
            user = await prisma.users.create({
                data: {
                    username: profile.email.toLowerCase().split('@')[0],
                    avatar: profile.picture,
                    firstName: profile.given_name,
                    lastName: profile.family_name,
                    email: profile.email.toLowerCase(),
                    isVerified: true,
                    password: await bcrypt.hash(crypto.randomBytes(20).toString('hex'), 10),
                    isPasswordSet: false
                },
            });
        }

        // Create JWT token
        const token = jwt.sign({ id: user.sys_id }, process.env.JWT_SECRET, {
            expiresIn: "7d",
        });

        // Set the cookie with HttpOnly and Secure flags
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            sameSite: 'strict',
        });

        // Redirect to frontend with success parameter
        res.redirect(`${process.env.FRONTEND_URL}`);
    } catch (error) {
        logger.error(`[/auth/google/callback] - ${error.message}`);
        next({ path: '/auth/google/callback', status: 500, message: "Authentication failed", extraData: error });
    }
};

const sendResetPasswordLink = async (req, res, next) => {
    try {
        const { email } = req.body;
        let user;

        if (email) {
            user = await prisma.users.findUnique({
                where: {
                    email: email.toLowerCase(),
                },
            });

            if (!user) {
                logger.warn(`[/auth/sendResetPasswordLink] - email not found`);
                logger.debug(`[/auth/sendResetPasswordLink] - email: ${email}`);
                return next({ path: '/auth/sendResetPasswordLink', status: 400, message: "Email not found" });
            }
        }

        if (!user) {
            const token = req.headers.authorization || req.cookies.token;

            if (!token) {
                logger.warn(`[/auth/sendResetPasswordLink] - token missing`);
                logger.debug(`[/auth/sendResetPasswordLink] - email: ${email}`);
                return next({ path: '/auth/sendResetPasswordLink', status: 400, message: "Token missing" });
            }

            try {
                const payload = jwt.verify(token, process.env.JWT_SECRET);
                user = await prisma.users.findUnique({
                    where: {
                        sys_id: payload.id
                    }
                });

                if (!user) {
                    logger.warn(`[/auth/sendResetPasswordLink] - user not found`);
                    logger.debug(`[/auth/sendResetPasswordLink] - email: ${email}`);
                    return next({ path: '/auth/sendResetPasswordLink', status: 400, message: "User not found" });
                }
            } catch (error) {
                logger.warn(`[/auth/sendResetPasswordLink] - invalid token`);
                logger.debug(`[/auth/sendResetPasswordLink] - email: ${email}`);
                return next({ path: '/auth/sendResetPasswordLink', status: 400, message: "Invalid token" });
            }
        }

        let resetToken = await prisma.passwordResetTokens.findFirst({
            where: {
                userId: user.sys_id,
                expiresAt: {
                    gte: new Date()  // Ensure the token is still valid
                }
            }
        });

        if (!resetToken) {
            const token = crypto.randomBytes(20).toString("hex");
            resetToken = await prisma.passwordResetTokens.create({
                data: {
                    userId: user.sys_id,
                    token,
                    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours from now
                },
            });
        }

        const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken.token}`;
        await mailer.sendResetPasswordLink(user.email, resetLink);

        logger.info(`[/auth/sendResetPasswordLink] - success - ${user.sys_id}`);
        logger.debug(`[/auth/sendResetPasswordLink] - email: ${user.email}`);

        return res.status(200).json({
            message: "Reset password link sent successfully",
        });
    } catch (error) {
        logger.error(`[/auth/sendResetPasswordLink] - ${error.message}`);
        next({ path: '/auth/sendResetPasswordLink', status: 500, message: error.message, extraData: error });
    }
};


const verifyResetPasswordLink = async(req, res, next) => {
    try {
        const { token } = req.params;
        const resetToken = await prisma.passwordResetTokens.findUnique({
            where: {
                token,
            },
        });

        if (!resetToken) {
            logger.warn(`[/auth/verifyResetPasswordLink] - token not found`);
            logger.debug(`[/auth/verifyResetPasswordLink] - token: ${token}`);
            return next({ path: '/auth/verifyResetPasswordLink', status: 400, message: "Invalid token" })
        }
        // match the token
        if (resetToken.token !== token) {
            logger.warn(`[/auth/verifyResetPasswordLink] - token mismatch`);
            logger.debug(`[/auth/verifyResetPasswordLink] - token: ${token}`);
            return next({ path: '/auth/verifyResetPasswordLink', status: 400, message: "Invalid token" })
        }
        if (resetToken.expiration < new Date()) {
            logger.warn(`[/auth/verifyResetPasswordLink] - token expired`);
            logger.debug(`[/auth/verifyResetPasswordLink] - token: ${token}`);
            return next({ path: '/auth/verifyResetPasswordLink', status: 400, message: "Token expired" })
        }
        const user = await prisma.users.findUnique({
            where: {
                sys_id: resetToken.userId,
            },
        });
        if (!user) {
            logger.error(`[/auth/verifyResetPasswordLink] - user not found`);
            logger.debug(`[/auth/verifyResetPasswordLink] - token: ${token}`);
            return next({ path: '/auth/verifyResetPasswordLink', status: 400, message: "User not found" })
        }
        
        logger.info(`[/auth/verifyResetPasswordLink] - success - ${user.sys_id}`);
        logger.debug(`[/auth/verifyResetPasswordLink] - id: ${user.sys_id}`);
        return res.status(200).json({
            isValid: true,
            message: "Link verified successfully",
        });
    } catch (err) {
        next({ path: '/auth/verifyResetPasswordLink', status: 400, message: err.message, extraData: err });
    }
}

const resetPassword = async(req, res, next) => {
    try {
        const { token, newPassword } = req.body;
        const resetToken = await prisma.passwordResetTokens.findUnique({
            where: {
                token,
            },
        });

        if (!resetToken) {
            logger.warn(`[/auth/resetPassword] - token not found`);
            logger.debug(`[/auth/resetPassword] - token: ${token}`);
            return next({ path: '/auth/resetPassword', status: 400, message: "Invalid token" })
        }
        // match the token
        if (resetToken.token !== token) {
            logger.warn(`[/auth/resetPassword] - token mismatch`);
            logger.debug(`[/auth/resetPassword] - token: ${token}`);
            return next({ path: '/auth/resetPassword', status: 400, message: "Invalid token" })
        }
        if (resetToken.expiration < new Date()) {
            logger.warn(`[/auth/resetPassword] - token expired`);
            logger.debug(`[/auth/resetPassword] - token: ${token}`);
            return next({ path: '/auth/resetPassword', status: 400, message: "Token expired" })
        }
        const user = await prisma.users.findUnique({
            where: {
                sys_id: resetToken.userId,
            },
        });
        if (!user) {
            logger.error(`[/auth/resetPassword] - user not found`);
            logger.debug(`[/auth/resetPassword] - token: ${token}`);
            return next({ path: '/auth/resetPassword', status: 400, message: "User not found" })
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        await prisma.users.update({
            where: {
                sys_id: user.sys_id,
            },
            data: {
                password: hashedPassword,
                isPasswordSet: true
            },
        });
        // delete reset token after password has been reset
        await prisma.passwordResetTokens.delete({
            where: {
                token,
            },
        });
        logger.info(`[/auth/resetPassword] - success - ${user.sys_id}`);
        logger.debug(`[/auth/resetPassword] - email: ${user.email}`);
        return res.status(200).json({
            message: "Password reset successfully",
        });
    } catch (err) {
        next({ path: '/auth/resetPassword', status: 400, message: err.message, extraData: err });
    }
}

module.exports = {
    register,
    login,
    verify,
    changePassword,
    sendVerificationMail,
    getUser,
    logout,
    continueWithGoogle,
    googleCallBack,
    sendResetPasswordLink,
    verifyResetPasswordLink,
    resetPassword
}