/ models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    firstName: String,
    lastName: String,
    age: Number,
    gender: String,
    role: { type: String, enum: ['admin', 'editor'], default: 'editor' },
    twoFASecret: String,
    twoFAEnabled: { type: Boolean, default: false },
});
userSchema.pre('save', async function (next) {
    if (this.role === 'admin') {
        const adminExists = await mongoose.model('User').findOne({ role: 'admin' });
        if (adminExists && adminExists._id.toString() !== this._id.toString()) {
            throw new Error('An admin already exists.');
        }
    }
    next();
});
module.exports = mongoose.model('User ', userSchema);
