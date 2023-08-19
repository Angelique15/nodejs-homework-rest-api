// middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../service/schemas/user');
const secret = process.env.SECRET;

const auth = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            status: 'error',
            code: 401,
            message: 'Unauthorized',
        });
    }

    const token = authHeader.replace('Bearer ', '');

    try {
        const payload = jwt.verify(token, secret);
        const user = await User.findOne({ _id: payload.id, token });

        if (!user) {
            return res.status(401).json({
                status: 'error',
                code: 401,
                message: 'Unauthorized',
            });
        }

        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).json({
            status: 'error',
            code: 401,
            message: 'Unauthorized',
        });
    }
};

module.exports = auth;
