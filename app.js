// app.js
const express = require('express');
const logger = require('morgan');
const cors = require('cors');
require("dotenv").config();
const contactsRouter = require('./api/contacts'); // Importa la ruta de los contactos
const authRouter = require('./api/users'); // Importa la ruta de autenticación


const app = express();

// Configuración de los archivos estáticos
app.use('/public', express.static('public'));

const formatsLogger = app.get('env') === 'development' ? 'dev' : 'short';

app.use(logger(formatsLogger));
app.use(cors());
app.use(express.json());

// Usa la ruta de autenticación para el registro y el inicio de sesión
app.use('/api/auth', authRouter);

// Middleware para verificar el token y proteger las rutas necesarias
app.use('/api/contacts', contactsRouter); // Usa la ruta de los contactos

app.use('/api/users', authRouter);


app.use((req, res) => {
  res.status(404).json({ message: 'Not found' });
});

app.use((err, req, res, next) => {
  res.status(500).json({ message: err.message });
});

module.exports = app;

