import { jwtVerify } from "jose"

export async function authMiddleware(req, res, done){
    console.log("Iniciando authMiddleware")

    try{
        const token = req.cookies?.token;

        if(!token){
            throw new Error("Token não encontrado")
        }

        const secret = new TextEncoder().encode(process.env.SECRET_KEY_JWT)

        const {payload} = await jwtVerify(token, secret)

        req.user = payload

        console.log("Payload decodificado:", req.user)

        console.log("Iniciando authRole")

        const allowedRole = "consumer"

        const roles = Array.isArray(allowedRole) ? allowedRole : [allowedRole]

        if(!roles.includes(req.user.role)){
            return res.status(403).send({error:"Acesso Negado"})
        }

        done()

        

    }catch(error){
        res.status(401).send({error:"Token invalido ou expirado"})
    }
}