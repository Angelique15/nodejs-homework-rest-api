const request = require('supertest');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const app = require('../app'); // Importa tu aplicación express
const User = require('../service/schemas/user'); // Importa tu modelo de usuario
const jwt = require('jsonwebtoken');
const secret = process.env.SECRET; // Importa el secreto para JWT

let authToken; // Almacenará el token para su uso en las pruebas
let testUser; // Almacenará el usuario de prueba para su uso en las pruebas
const loginEndpoint = '/api/users/login'; // Ruta al endpoint de inicio de sesión
const currentUserEndpoint = '/api/users/current'; // Ruta al endpoint de usuario actual

beforeAll(async () => {
    try {
        await mongoose.connect(process.env.DB_HOST, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });

        // Crea un usuario de prueba
        const hashedPassword = await bcrypt.hash('123456700', 10);
        testUser = await User.create({
            email: 'itachigod@example.com',
            password: hashedPassword,
        });

        // Genera un token válido para el usuario de prueba
        authToken = jwt.sign({ id: testUser._id, email: testUser.email }, secret, { expiresIn: '1h' });

        // Agrega un console.log para verificar el token generado
        console.log('Generated Token:', authToken);
    } catch (error) {
        console.error('Error during beforeAll:', error);
    }
});


afterAll(async () => {
    if (testUser) {
        // Elimina el usuario de prueba y cierra la conexión a la base de datos
        await User.deleteOne({ _id: testUser._id });
    }
    await mongoose.connection.close();
});


describe('Authentication Controller', () => {
    it('should log in successfully and return a token', async () => {
        const response = await request(app)
            .post(loginEndpoint)
            .send({ email: 'miramar@example.com', password: '123456789' });

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('token');
        const token = response.body.token;
        // Verifica si el token es un string no vacío
        expect(typeof token).toBe('string');
        expect(token.length).toBeGreaterThan(0);
    });


    it('should not get the current user with invalid token', async () => {
        const response = await request(app)
            .get(currentUserEndpoint)
            .set('Authorization', 'Bearer invalidtoken');

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('status', 'error'); // Cambio en la propiedad esperada
        expect(response.body).toHaveProperty('code', 401); // Cambio en la propiedad esperada
        expect(response.body).toHaveProperty('message', 'Unauthorized');
    });


});




