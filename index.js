const express = require('express');
const app = express();
const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config();
const userRoute = require('./routes/user');
const authRoute = require('./routes/auth');
const productRoute = require('./routes/product');
const cartRoute = require('./routes/carts')
const orderRoute = require('./routes/order')
const cors = require('cors');



mongoose.
connect(process.env.MONGO_URL)
.then(()=>console.log("DB connection successful")).
catch((err)=>{console.log(err)})


app.use(cors())
app.use(express.json());
app.use("/api/users", userRoute);
app.use("/api/auth", authRoute);
app.use("/api/products", productRoute);
app.use("/api/carts", cartRoute);
app.use("/api/orders", orderRoute);



app.listen(process.env.PORT || 5000, ()=> {
    console.log('Server is running on port 5000');
})

