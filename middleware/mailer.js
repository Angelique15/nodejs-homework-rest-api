const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
    },
});

async function sendEmail(toEmail, verificationLink) { // Agregamos 'verificationLink' como parámetro
    try {
        const info = await transporter.sendMail({
            from: '"Angelique 👻" <mar.angel.go15@gmail.com>',
            to: toEmail,
            subject: "Verificación de correo electrónico ✔",
            html: `Haga clic en el siguiente enlace para verificar su correo electrónico: <a href="${verificationLink}">${verificationLink}</a>`
        });

        console.log("Message sent: %s", info.messageId);
    } catch (error) {
        console.error("Error sending email:", error);
    }
}

module.exports = sendEmail;


