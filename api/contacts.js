// api/contacts.js (Updated protected route)
const express = require('express');
const controller = require('../controller');
const auth = require('../middleware/auth');

const router = express.Router();

router.get('/', auth, controller.getAllContacts);
router.get('/:contactId', auth, controller.getContactById);
router.post('/', auth, controller.createContact);
router.put('/:contactId', auth, controller.updateContact);
router.delete('/:contactId', auth, controller.deleteContact);
router.patch('/:contactId/favorite', auth, controller.updateStatusContact);

module.exports = router;



