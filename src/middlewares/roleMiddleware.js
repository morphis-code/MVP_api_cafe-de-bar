export async function roleMiddleware(allowedRole){
    console.log("Iniciando roleMiddleware")
    return (req, res, done) => {

        const roles = Array.isArray(allowedRole) ? allowedRole : [allowedRole];

        if(!roles.includes(req.user.role)){
            return res.status(403).send({error:"Acesso negado"})
        }
        done()
    }
}