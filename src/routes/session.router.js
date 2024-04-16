import { Router } from 'express';
import passport from 'passport';
import { generateJWToken } from '../utils.js'
import { passportCall, authorization } from "../utils.js";
const router = Router();


router.get('/github', passport.authenticate('github', { scope: ['user:email'] }), async (req, res) => {
})

router.get('/githubcallback', passport.authenticate('github', { failureRedirect: '/github/error' }), async (req, res) => {
    const user = req.user

    req.session.user = {
        name: `${user.first_name} ${user.last_name}`,
        email: user.email,
        age: user.age
    }
    req.session.admin = true;
    res.redirect("/products")
})

router.post("/register", passport.authenticate('register', { failureRedirect: '/api/sessions/fail-register' }), async (req, res) => {
    console.log("Registrando nuevo usuario.");
    res.status(201).send({ stauts: 'success', message: "User creado de forma exitosa!!" })
}
);

router.post("/login", passport.authenticate('login', { failureRedirect: '/api/sessions/fail-login' }), async (req, res) => {
    console.log("User found to login:");
    const user = req.user;    
    console.log(user);

    if (!user) return res.status(401).send({ status: "error", error: "El usuario y la contraseña no coinciden!" });
/* 
  req.session.user = {
        name: `${user.first_name} ${user.last_name}`,
        email: user.email,
        age: user.age
    }
    res.send({ status: "success", payload: req.session.user, message: "¡Primer logueo realizado! :)" }); 
 */
    const access_token = generateJWToken(user)
        console.log(access_token);
        res.send({ access_token: access_token }) 

});

router.get("/fail-register", (req, res) => {
    res.status(401).send({ error: "Failed to process register!" });
});

router.get("/fail-login", (req, res) => {    
    res.status(401).send({ error: "Failed to process login!" });    
});



// Endpoint que renderiza la vista del perfil de usuario
router.get("/current",
    // authToken, //-> Usando Authorization Bearer Token
    //passport.authenticate('jwt', { session: false }), //-> Usando JWT por Cookie
    passportCall('jwt'), //-> Usando passport-JWT por Cookie mediante customCall
    authorization('user'),
    (req, res) => {
        console.log("::::::OBJETO req en users.views.router.js::::::");
        // console.log(req.user);
        res.render("profile", {
            user: req.user
        });
    }
);






export default router;