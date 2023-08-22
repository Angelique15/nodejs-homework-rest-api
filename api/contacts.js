// api/contacts.js (Updated protected route)
const express = require('express');
const controller = require('../controller');
const auth = require('../middleware/auth'); // Import the authentication middleware

const router = express.Router();

router.get('/', auth, controller.getAllContacts); // Use auth middleware
router.get('/:contactId', auth, controller.getContactById); // Use auth middleware
router.post('/', auth, controller.createContact); // Use auth middleware
router.put('/:contactId', auth, controller.updateContact); // Use auth middleware
router.delete('/:contactId', auth, controller.deleteContact); // Use auth middleware
router.patch('/:contactId/favorite', auth, controller.updateStatusContact); // Use auth middleware

module.exports = router;


