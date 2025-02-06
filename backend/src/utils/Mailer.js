const nodemailer = require("nodemailer");
const logger = require("./Logger");

class Mailer {
    from = process.env.GMAIL;
    transporter;
    constructor() {
        this.transporter = nodemailer.createTransport({
            service: "gmail",
            host: "smtp.gmail.com",
            port: 587,
            secure: false,
            auth: {
                user: process.env.MAILER_MAIL,
                pass: process.env.MAILER_SECRET,
            },
        });
        this.sendMail = this.sendMail.bind(this);
    }

    async sendMail(to, subject, body) {
        return await this.transporter.sendMail({
            from: { name: process.env.MAILER_NAME, address: process.env.MAILER_MAIL }, // sender address
            to, // list of receivers
            subject: subject, // Subject line
            ...body
        })
    }

    async sendResetPasswordLink(email, link) {
        try {

            const body = {
                html: `
<div
    style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
    <h2 style="text-align: center; color: #333;">Reset Password</h2>
    <p>Hello,</p>
    <p>Please reset your password by clicking the button below:</p>
    <div style="text-align: center; margin: 20px 0;">
        <a href="${link}"
            style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 16px;">Reset
            Password</a>
    </div>
    <p>If you did not request this, please ignore this email.</p>
    <p style="color: #888;">Thank you, <br /> ${process.env.SITE_NAME}</p>
</div>`
            }
            await this.sendMail([email], 'Reset Password', body);

        }
        catch (error) {
            logger.error(`[/forgotpassword/resetpassword] - ${error.stack}`);
        }
    }

    async sendVerificationLink(email, link) {
        try {

            const body = {
                html: `
<div
    style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
    <h2 style="text-align: center; color: #333;">Email Verification</h2>
    <p>Hello,</p>
    <p>Please verify your email by clicking the button below:</p>
    <div style="text-align: center; margin: 20px 0;">
        <a href="${link}"
            style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 16px;">Verify
            Email</a>
    </div>
    <p>If you did not request this, please ignore this email.</p>
    <p style="color: #888;">Thank you, <br /> ${process.env.SITE_NAME}</p>
</div>`
            }
            await this.sendMail([email], 'Verify account', body);

        } catch (error) {
            logger.error(`[/forgotpassword/resetpassword] - ${error.stack}`);
        }

    }


}

module.exports = new Mailer();