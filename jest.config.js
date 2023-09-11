// jest.config.js
module.exports = {
    testEnvironment: 'node',
    transform: {
        '^.+\\.ts?$': 'ts-jest',
    },
    moduleFileExtensions: ['ts', 'js', 'json', 'node'],
    testTimeout: 10000, // 10 segundos en milisegundos
};

