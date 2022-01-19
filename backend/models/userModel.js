const mongoose = require('mongoose');
const validator = require('validator');
const becrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto')

const userSchema = new mongoose.Schema({

    name: {
        type: String,
        require: [true, "Please Enter your Name"],
        maxLength: [30, "Name cannot exceed 30 characters"],
        minLength: [4, "Name should have more then 4 characters"]
    },
    email: {
        type: String,
        required: [true, "Please Enter your Email"],
        unique: true,
        validator: [validator.isEmail, "Please Enter a Valid Email"],
    },
    password: {
        type: String,
        required: [true, "Please Enter your Password"],
        minLength: [8, "Password should be greater then 8 characters"],
        select: false
    },
    avatar: {
            public_id: {
                type: String,
                required: true
            },
            url: {
                type: String,
                required: true
        }
    },
    role: {
        type: String,
        default: "user"
    },
    createdAt: {
        type: Date,
        default: Date.now,
      },

    resetPasswordToken: String,
    resetPasswordExpire: Date,
});

userSchema.pre("save", async function(next) {

    if(!this.isModified("password")){
        next();
    }

    this.password = await becrypt.hash(this.password,10);
});

// JWT TOKEN
userSchema.methods.getJWToken = function () {
    return jwt.sign({ id: this._id}, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRE,
    });
};

// Compare Password

userSchema.methods.comparePassword = async function(enterePassword){
    return await becrypt.compare(enterePassword, this.password);
};

// Generating Password Reset token

userSchema.methods.getResetPasswordToken =  function () {

    // Generating Token
    const resetToken = crypto.randomBytes(20).toString('hex');


    // Hassing and Adding restPasswordToken to user schema
    this.resetPasswordToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest('hex');

    
    this.resetPasswordExpire = Date.now() + 15 * 60 * 1000;
    
    return resetToken;
};




module.exports = mongoose.model('User', userSchema);