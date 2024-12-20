const Carts  = require('../models/Carts');
const { verifyToken, verifyTokenAndAuthorization, verifyTokenAndAdmin } = require('./verifyToken');

const router = require('express').Router();

//CREATE

router.post("/", verifyToken, async (req, res)=> {
    const newCart = new Carts(req.body)
    console.log(newCart)

    try{
        const savedCart = await newCart.save()
        console.log(savedCart)
       return res.status(200).json(savedCart)
    }catch (err){
        console.log(err)
        return res.status(500).json(err)
    }

})


// //UPDATE CART

router.put("/:id", verifyTokenAndAuthorization, async (req, res) => {
        try{
            const updatedCart = await Cart.findByIdAndUpdate (req.params.id, {
                $set: req.body
            },{new:true})
            console.log(updatedCart)
            return res.status(200).json(updatedCart)
        }catch(err) {
            console.log(err)
           return res.status(500).json(err)
        }
})

// //DELETE PRODUCT
router.delete("/:id", verifyTokenAndAuthorization, async (req, res)=> {
    try{
        await Cart.findByIdAndDelete(req.params.id)
        res.status(500).json("Cart has been deleted...")
    }catch(err){
        res.status(500).json(err)
    }
})

// // //GET USER CART
router.get("/find/:userId", verifyTokenAndAuthorization, async (req, res)=> {
    try{
       const cart =  await Cart.findOne({userId: req.params.userId})
       res.status (200).json(cart);
        }catch(err){
        res.status(500).json(err)
    }
})

// // //GET USER ALL

router.get("/", verifyTokenAndAdmin, async (req, res)=> {
    try{
        const carts = await Cart.find()
        res.status(200).json(carts);
    }catch(err){
        res.status(500).json(err)
    }
})




module.exports = router;