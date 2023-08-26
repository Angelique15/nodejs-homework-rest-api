import request from 'supertest';
import app from '../app';
const User = require('../service/schemas/user');

describe('Authentication Controller', () => {
    beforeEach(async () => {
        console.log('Running beforeEach');
        await User.deleteMany({});
        const newUser = new User({
            email: 'Ningning@example.com',
            password: 'ning123',
        });
        await newUser.save();
    });

    it('should respond with a 200 status and return a token and user object', async () => {
        const response = await request(app)
            .post('/api/auth/login')
            .send({ email: 'Ningning@example.com', password: 'ning123' });

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('token');
        expect(response.body).toHaveProperty('user');
        expect(response.body.user).toHaveProperty('email', 'Ningning@example.com');
        expect(response.body.user).toHaveProperty('subscription');
    });
});

