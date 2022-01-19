const mongoose = require('mongoose');

const connectDatabase = () => {
    mongoose.connect(process.env.DB_URI,{

    }). then((data) => {
        console.log(`MongoDB connected with server: ${data.connection.host}`);
    })
    .catch((error) => {
        console.log({msg: error.message})
    });
};


module.exports = connectDatabase