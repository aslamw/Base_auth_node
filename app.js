// imports
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//error correction Objectid
const ObjectId = mongoose.Types.ObjectId

//config json
app.use(express.json())

//Modes
const User = require('./models/user')

//route private
app.get('/user/:id', checkToken,async (req,res) => {
    const id = new ObjectId(req.params.id)
   
    const user = await User.findById(id, '-password')

    if(!user){
        return res.status(404).json({msg:"não encontrado"})
    }

    res.status(200).json({user})
})

//function check auth user
function checkToken(req, res, next){
    //const headertoken = req.headers
    const headertoken = req.headers["authorization"]
    const token = headertoken && headertoken.split(" ")[1]

    if(!token){
        return res.status(401).json({msg:"acesso negado"})
    }

    try{
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()
        //res.status(200).json({token})
        
    }catch(err){
        res.status(400).json({msg:"token invalido"})
    }

}

//route public
app.get('/', (req,res) => {
    res.status(200).json({msg: "teste 1 ok"})
})

//Register user
app.post('/auth/register', async(req,res) => {
    const {name, email, password, confirmpassword} = req.body

    if(!name){
        return res.status(422).json({msg:"O nome é obrigatorio"})
    }
    if(!email){
        return res.status(422).json({msg:"O email é obrigatorio"})
    }
    if(!password){
        return res.status(422).json({msg:"O password é obrigatorio"})
    }
    if(!confirmpassword){
        return res.status(422).json({msg:"O confirmpassword  é obrigatorio"})
    }
    if (password !== confirmpassword){
        return res.status(422).json({msg:"O password não é semelhante"})
    }

    //check  if users exists
    const userExist = await User.findOne({email: email})

    if(userExist){
        return res.status(422).json({msg:"usuario já existe"})
    }

    //creat password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user
    const user = new User({
        name,
        email,
        password: passwordHash
    }) 

    try {
        await user.save()
        res.status(201).json({msg:"usuário criado"})
    }
    catch (err){
        console.log(err)
        res
            .status(500)
            .json({msg:"erro no servidor"})
    }

})

//login
app.post("/auth/login", async (req,res) => {
    const {email, password} = req.body

    //validations
    if(!email){
        return res.status(422).json({msg:"O email é obrigatorio"})
    }
    if(!password){
        return res.status(422).json({msg:"O password é obrigatorio"})
    }

    //check if user exists
    const userExist = await User.findOne({email: email})

    if(!userExist){
        return res.status(404).json({msg:"usuario não existe"})
    }

    //check if password match
    const passExist = await bcrypt.compare(password, userExist.password)

    if(!passExist){
        return res.status(404).json({msg:"senha errada digite novamente"})
    }

    try {
        const SECRET = process.env.SECRET

        const token = jwt.sign(
            {
                id: userExist._id
            },
            SECRET
        )
        res.status(200).json({msg:"sucesso",token})
    }
    catch (err){
        console.log(err)
        res
            .status(500)
            .json({msg:"erro no servidor"})
    }


})

//Credencials .env
const dbuser = process.env.DB_USER
const dbpass = process.env.DB_PASS

// connected MongoDB
mongoose
    .connect(
        `mongodb+srv://marcosw:${dbpass}@teste.laio7mj.mongodb.net/?retryWrites=true&w=majority`
    )
    .then(() => {
        console.log('connected')
        app.listen(3000)
    })
    .catch((err) =>{console.group(err)})

