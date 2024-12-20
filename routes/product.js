const Product  = require('../models/Products');
const { verifyToken, verifyTokenAndAuthorization, verifyTokenAndAdmin } = require('./verifyToken');

const router = require('express').Router();

//CREATE

router.post("/", verifyTokenAndAdmin, async (req, res)=> {
    const newProduct = new Product(req.body)
    console.log(newProduct)

    try{
        const savedProduct = await newProduct.save()
        console.log(savedProduct)
       return res.status(200).json(savedProduct)
    }catch (err){
        console.log(err)
        return res.status(500).json(err)
    }

})


// //UPDATE

router.put("/:id", verifyTokenAndAdmin, async (req, res) => {
        try{
            const updatedProduct = await Product.findByIdAndUpdate (req.params.id, {
                $set: req.body
            },{new:true})
            console.log(updatedUser)
            return res.status(200).json(updatedProduct)
        }catch(err) {
            console.log(err)
           return res.status(500).json(err)
        }
})

//DELETE PRODUCT
router.delete("/:id", verifyTokenAndAdmin, async (req, res)=> {
    try{
        await Product.findByIdAndDelete(req.params.id)
        res.status(500).json("Product has been deleted...")
    }catch(err){
        res.status(500).json(err)
    }
})

// //GET PRODUCT
router.get("/find/:id", async (req, res)=> {
    try{
       const product =  await Product.findById(req.params.id)
       res.status (200).json(product);
        }catch(err){
        res.status(500).json(err)
    }
})

// //GET USER ALL PRODUCTS
router.get("/", async (req, res)=> {
    const qNew = req.query.new;
    const qCategory = req.query.category;

    try{
        let product;

        if(qNew){
            products = await Product.find().sort({createdAt: -1}).limit(5)
        }else if (qCategory){
            products = await Product.find({categories:{
                $in:[qCategory],
            }})
        }else{
            products =  await Product.find();
        }



       res.status(200).json(products);
        }catch(err){
        res.status(500).json(err)
    }
})





module.exports = router;