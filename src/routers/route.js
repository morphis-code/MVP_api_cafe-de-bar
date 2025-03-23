import {jwtVerify, SignJWT} from "jose"
import bcrypt from "bcryptjs"
import { manipulationMongoDb } from "../db/mongodb.js"
import { authMiddleware } from "../middlewares/authMiddleware.js"
import { roleMiddleware } from "../middlewares/roleMiddleware.js"

export default async function router(app, options){
    
    app.post("/register", async(req, res)=>{
        const {name, email, sex, password, role} = req.body

        if(!name || !email || !sex || !password || !role){
            res.status(409).send({message:"Todos os campos precisam ser preenchidos"}) 
        }

        const cryptPassword = bcrypt.hashSync(password, 10)

        const instance = manipulationMongoDb("teste","users")

        await instance.insertOne({name, email, sex, password:cryptPassword, role})

        const id = await instance.findOne({email:email})

        const secretJwt = new TextEncoder().encode(process.env.SECRET_KEY_JWT)
        const token = await new SignJWT({email, id:id._id.toString(), role})
        .setProtectedHeader({alg:"HS256"})
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(secretJwt)

        res.setCookie("token", token, {
            httpOnly: true,
            path:"/",
            maxAge:3600,
            secure:true,
            sameSite:"Lax"
        })

        res.status(200).send({message:"Usuário criado!!", token})


    })

    app.post("/login",{preHandler: authMiddleware}, async(req, res)=>{
        const {email, password} = req.body

        const instance = manipulationMongoDb("teste","users")

        const user = await instance.findOne({email:email})

        if(!user){
           return res.status(400).send({message:"Usuário não encontrado"})
        }

        const passwordMatch = bcrypt.compareSync(password, user.password)

        if(!passwordMatch){
            return res.status(400).send({message:"Senha ou email invalido"})
        }

        const secretJwt = new TextEncoder().encode(process.env.SECRET_KEY_JWT)
        const token = await new SignJWT({email, id:user._id.toString(), role:user.role})
        .setProtectedHeader({alg:"HS256"})
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(secretJwt)

        res.cookie("token", token, {
            httpOnly: true,
            path:"/",
            maxAge:3600,
            sameSite:"Lax"
        })

        res.status(200).send({message:"Logado com sucesso", token})

    })
}