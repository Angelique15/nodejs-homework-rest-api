// api/users.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const User = require('../service/schemas/user');
const authMiddleware = require('../middleware/auth');
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
        await newUser.save();

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

module.exports = router;