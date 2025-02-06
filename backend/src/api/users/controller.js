const prisma = require('../../utils/PrismaClient');
const crypto = require("crypto");
const logger = require('../../utils/Logger');
const mailer = require('../../utils/Mailer')

const getUser = async (req, res, next) => {
    try {
        const user = req.user;
        if (!user) {
            logger.warn(`[/users/getUser] - user not found`);
            logger.debug(`[/users/getUser] - user: ${req.user.sys_id}`);
            return next({ path: '/users/getUser', status: 400, message: "User not found" })
        }
        logger.info(`[/users/getUser] - success - ${user.sys_id}`);
        logger.debug(`[/users/getUser] - user: ${user.sys_id}`);
        delete user.password;
        delete user.sys_id;
        return res.status(200).json({
            user,
        });
    } catch (err) {
        next({ path: '/users/getUser', status: 400, message: err.message, extraData: err });
    }
}

const updateUser = async (req, res, next) => {
    try {
        const { firstName, lastName, email, avatar } = req.body;
        const user = req.user;

        // Check if the new email is already in use
        if (email && email.toLowerCase() !== user.email.toLowerCase()) {
            const emailUser = await prisma.users.findUnique({
                where: { email: email.toLowerCase() },
            });

            if (emailUser) {
                logger.warn(`[/users/updateUser] - email already exists`);
                logger.debug(`[/users/updateUser] - email: ${email}`);
                return next({ path: '/users/updateUser', statusCode: 400, message: "Email already exists" });
            }
        }

        // Update user information
        const updatedUser = await prisma.users.update({
            where: { email: user.email },
            data: {
                firstName: firstName || user.firstName,
                lastName: lastName || null,
                email: email ? email.toLowerCase() : user.email,
                isVerified: email.toLowerCase() === user.email.toLowerCase() ? user.isVerified : false,
                avatar: avatar == null ? null : (avatar || user.avatar)
            },
        });

        // Send verification email if email is updated
        if (email && email.toLowerCase() !== user.email.toLowerCase()) {
            const token = crypto.randomBytes(20).toString("hex");
            const verificationToken = await prisma.verificationTokens.create({
                data: {
                    userId: updatedUser.sys_id,
                    token,
                    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours from now
                },
            });
            const verificationLink = `${process.env.FRONTEND_URL}/verify/${verificationToken.token}`;
            await mailer.sendVerificationLink(updatedUser.email, verificationLink);
        }

        logger.info(`[/users/updateUser] - success - ${updatedUser.sys_id}`);
        logger.debug(`[/users/updateUser] - userId: ${updatedUser.sys_id}`);

        // Remove sensitive data from user object
        delete updatedUser.password;
        delete updatedUser.sys_id;

        return res.status(200).json({
            user: updatedUser,
            message: "User information updated successfully",
        });
    } catch (err) {
        next({ path: '/users/updateUser', statusCode: 400, message: err.message, extraData: err });
    }
}

module.exports = {
    getUser,
    updateUser
}