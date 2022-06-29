require('dotenv').config()
const express = require ('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { application } = require('express')




const app = express()

//JSON RESPONSE
app.use(express.json())

//Models
const User = require('./models/User')


//ROTA PÚBLICA
app.get('/', (req,res) =>{
    res.status(200).json({msg: 'Bem vindo a nossa API'
    })
})

//Private route
app.get('/user/:id', checkToken, async (req,res) =>{
    const id = req.params.id

    //check if user already exists.
    const user = await User.findById(id, '-password')

    if(!user){
        return res.status(404).json({msg: 'Usuário não encontrado.'})
    }

    return res.status(200).json({user})    
    
})

function checkToken(req,res,next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token){
        //Status 401 - Acesso negado no sistema
        return res.status(401).json({msg: "Access denied."})
    }

    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        //If it is correct, you call next() to advance middleware.
        next()
        
    } catch (error) {
        console.log(error)
        //Status 400 - Forbidden
        res.status(400).json({msg: 'Token inválido.'})
        
    }
}

//Registrar usuário
app.post('/auth/register', async (req,res) =>{
    //Uma boa prática, é sempre usar a desestruturação sempre que as variáveis tiverem os mesmos nomes da requisiçao, pois deixa o código mais limpo, e recebe tudo dentro de um único req.body.
    const {name, email, password, confirmpassword} = req.body

    if(!name){
        return res.status(422).json({msg: 'O nome é obrigatório.'})
    }

    if(!email){
        return res.status(422).json({msg: 'O email é obrigatório.'})
    }

    if(!password){
        return res.status(422).json({msg: 'A senha é obrigatória.'})
    }

    if(password != confirmpassword){
        return res.status(422).json({msg: 'As senhas não conferem.'})
    }

    //check if user already exists.
    const userExists = await User.findOne({email: email})
    if(userExists){
        return res.status(422).json({msg: 'Já existe um usuário cadastrado com esse endereço de e-mail'})
    }

    //create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user
    const user = new User({
        name,
        email,
        //Necessário passar a variável 'password' recebendo a 'passwordHash', pois na model, a variável é 'password'.
        password: passwordHash
    });

    try {
        await user.save()
        res.status(201).json({msg: 'Usuário criado com sucesso.'})
    }catch(error){
        console.log(error)
        res.status(500).json({msg: 'Ocorreu um erro no servidor. Tente novamente.', error})

    }

})

//Login user
app.post('/auth/login', async (req,res) =>{

    //Recendo os dados nas variáveis
    const {email, password} = req.body
    //Validações de campo
    if(!email){
        return res.status(422).json({msg: 'O email é obrigatório.'})
    }

    if(!password){
        return res.status(422).json({msg: 'A senha é obrigatória.'})
    }

    //Check if user already exists.
    const user = await User.findOne({email: email})
    if(!user){
        return res.status(404).json({msg: 'Usuário não encontrado.'})
    }

    //check if password match
    const checkPassword = await bcrypt.compare(password, user.password)
    //Aqui fazemos a validação, transformando a variável em falsa, para caso a 'checkPassword' se encontre como 'false'
    //significa que o bcrypt comparou as duas senhas, e não são iguais.
    if(!checkPassword){
        return res.status(422).json({msg: 'Senha inválida.'})
    }

    
    //Parte de autenticar e gerar o token
    try{
        const secret = process.env.SECRET

        const token = jwt.sign(
            {
            id: user._id,
            },secret
        )

        res.status(200).json({msg: 'Autenticação realizada com sucesso.', token})
    }catch{
        console.log(error)
        res.status(500).json({msg: 'Ocorreu um erro no servidor. Tente novamente.', error})
    }




})


//Credentials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.spnx6se.mongodb.net/?retryWrites=true&w=majority`).then(() =>{
    app.listen(3000)
    console.log('Servidor rodando! http://localhost:3000 | Conectado ao BD!')
}).catch((err) =>{
    console.log('Ocorreu um erro: ',err )
})



