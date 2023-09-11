// api/users.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const User = require('../service/schemas/user');
const authMiddleware = require('../middleware/auth');
const sendEmail = require('../middleware/mailer');
const multer = require('multer');
const path = require('path');
const gravatar = require('gravatar'); // Importa el paquete gravatar
const fs = require('fs/promises');
const jimp = require('jimp');
const { v4: uuidv4 } = require('uuid');


const router = express.Router();

const secret = process.env.SECRET;
// Configuración de Multer
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/avatars'); // La carpeta donde se guardarán los avatares
    },
    filename: function (req, file, cb) {
        // Generar un nombre de archivo único
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, uniqueSuffix + ext);
    }
});

const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type'), false);
    }
};

const upload = multer({ storage: storage, fileFilter: fileFilter });


// Ruta para actualizar el avatar
router.patch('/avatars', authMiddleware, upload.single('avatar'), async (req, res) => {
    try {
        const user = req.user;
        const tempPath = req.file.path;

        // Mover el archivo de tmp a la ubicación final (public/avatars)
        const uniqueFilename = `${uuidv4()}${path.extname(tempPath)}`;
        const newPath = path.join('public', 'avatars', uniqueFilename);

        await fs.rename(tempPath, newPath);

        // Procesar la imagen con jimp y asignarle dimensiones de 250x250
        const image = await jimp.read(newPath);
        await image.resize(250, 250).write(newPath);

        // Actualizar la URL del avatar en el usuario
        user.avatarURL = `avatars/${uniqueFilename}`;
        await user.save();

        res.status(200).json({ avatarURL: user.avatarURL });
    } catch (error) {
        res.status(500).json({ message: 'Internal Server Error' });
    }
});


router.post('/signup', async (req, res) => {
    try {
        // Validación de la solicitud de registro usando Joi
        const schema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().min(6).required(),
        });

        const { error } = schema.validate(req.body);
        if (error) {
            return res.status(400).json({ message: error.details[0].message });
        }

        const { email, password } = req.body;

        // Verificar si el correo ya está en uso
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: 'Email in use' });
        }

        // Generar la URL del avatar utilizando gravatar
        const avatarURL = gravatar.url(email, { s: '200', r: 'pg', d: 'identicon' });

        // Hash de la contraseña usando bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);

        // Crear un nuevo usuario en la base de datos
        const newUser = new User({ email, password: hashedPassword, avatarURL });

        // Generar un token de verificación único
        const verificationToken = uuidv4();

        // Asigna el token de verificación al usuario
        newUser.verificationToken = verificationToken;
        await newUser.save();

        // Genera el enlace de verificación
        const verificationLink = `${process.env.CLIENT_URL}/users/verify/${verificationToken}`;

        // Envía el correo electrónico de verificación
        await sendEmail(newUser.email, verificationLink);

        // Respuesta exitosa
        res.status(201).json({
            user: {
                email: newUser.email,
                subscription: newUser.subscription,
                avatarURL,
            }
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal Server Error' });
    }
});


// Login Route
router.post('/login', async (req, res, next) => {
    try {
        // Validación de la solicitud de inicio de sesión usando Joi
        const schema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().required(),
        });

        const { error } = schema.validate(req.body);
        if (error) {
            return res.status(400).json({ message: error.details[0].message });
        }

        const { email, password } = req.body;

        // Buscar al usuario por correo electrónico
        const user = await User.findOne({ email });

        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Email or password is wrong' });
        }

        // Verificar si el correo está verificado
        if (!user.verify) {
            return res.status(401).json({ message: 'Email is not verified' });
        }

        // Crear un token JWT
        const token = jwt.sign({ id: user._id, email: user.email }, secret, { expiresIn: '1h' });

        // Actualizar el token en el modelo de usuario
        user.token = token;
        await user.save();

        // Respuesta exitosa
        res.json({
            token,
            user: {
                email: user.email,
                subscription: user.subscription
            }
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal Server Error' });
    }
});


// Ruta de logout con el middleware de autenticación
router.get('/logout', authMiddleware, async (req, res) => {
    try {
        const user = await User.findOne({ _id: req.user._id });

        if (!user) {
            return res.status(401).json({ message: 'Not authorized' });
        }

        user.token = ''; // Elimina el token en el usuario
        await user.save();

        res.status(204).send(); // Respuesta exitosa sin contenido
    } catch (error) {
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Ruta para obtener los datos del usuario actual con el middleware de autenticación
router.get('/current', authMiddleware, (req, res) => {
    try {
        const { email, subscription } = req.user;

        res.status(200).json({
            email,
            subscription,
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Ruta para verificar el correo electrónico
router.get('/verify/:verificationToken', async (req, res) => {
    try {
        const verificationToken = req.params.verificationToken;

        // Buscar al usuario por el token de verificación
        const user = await User.findOne({ verificationToken });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Actualizar el usuario para marcarlo como verificado y eliminar el token de verificación
        user.verify = true;
        user.verificationToken = null;
        await user.save();

        res.status(200).json({ message: 'Verification successful' });
    } catch (error) {
        console.error(error); // Agrega esta línea para obtener información sobre el error
        res.status(500).json({ message: 'Internal Server Error' });
    }
});


// Ruta para reenviar el correo de verificación
router.post('/users/verify', async (req, res) => {
    try {
        const { email } = req.body;

        // Validar si el campo "email" está presente en el cuerpo de la solicitud
        if (!email) {
            return res.status(400).json({ message: 'Missing required field: email' });
        }

        // Buscar al usuario por correo electrónico
        const user = await User.findOne({ email });

        // Verificar si el usuario existe
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Verificar si el usuario ya está verificado
        if (user.verify) {
            return res.status(400).json({ message: 'Verification has already been passed' });
        }

        // Generar un nuevo token de verificación
        const verificationToken = uuidv4();

        // Asignar el nuevo token al usuario
        user.verificationToken = verificationToken;
        await user.save();

        // Generar el enlace de verificación
        const verificationLink = `${process.env.CLIENT_URL}/users/verify/${verificationToken}`;

        // Envía el correo electrónico de verificación
        await sendEmail(user.email, verificationLink);

        // Respuesta exitosa
        res.status(200).json({ message: 'Verification email sent' });
    } catch (error) {
        res.status(500).json({ message: 'Internal Server Error' });
    }
});



module.exports = router;