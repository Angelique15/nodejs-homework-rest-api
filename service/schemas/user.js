// service/schemas/user.js
const mongoose = require('mongoose');
const gravatar = require('gravatar'); // Importa el paquete gravatar

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
    },
    subscription: {
        type: String,
        enum: ['starter', 'pro', 'business'],
        default: 'starter',
    },
    token: {
        type: String,
        default: null,
    },
    avatarURL: String, // Agrega la propiedad avatarURL al esquema
});

// Antes de guardar un nuevo usuario, genera la URL del avatar utilizando gravatar
userSchema.pre('save', function (next) {
    if (!this.avatarURL) {
        const avatarURL = gravatar.url(this.email, { s: '200', r: 'pg', d: 'identicon' });
        this.avatarURL = avatarURL;
    }
    next();
});

module.exports = mongoose.model('User', userSchema);

