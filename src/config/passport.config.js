import { createHash, isValidPassword } from '../utils.js';
import passportLocal from 'passport-local';
import GitHubStrategy from 'passport-github2';
import passport from 'passport';
import userModel from '../dao/models/user.model.js';
import jwtStrategy from 'passport-jwt';
import { PRIVATE_KEY } from '../utils.js';
import cartManager from "../dao/cartManager.js";
const carts = new cartManager();

const localStrategy = passportLocal.Strategy;
const JwtStrategy = jwtStrategy.Strategy;
const ExtractJWT = jwtStrategy.ExtractJwt;

const initializePassport = () => {
    //Estrategia de obtener Token JWT por Cookie:
    // TODO:: A Implementar

    passport.use('jwt', new JwtStrategy(
        {
            jwtFromRequest: ExtractJWT.fromExtractors([cookieExtractor]),
            secretOrKey: PRIVATE_KEY
        },
        async (jwt_payload, done) => {
            console.log("Entrando a pastport Strategy con JWT");
            try {
                console.log("JWT Objetnido del Payload");
                console.log(jwt_payload);
                return done(null, jwt_payload.user)
            } catch (error) {
                console.log(error);
                return done(error)
            }

        }
    ))



/*
=============================================
                GitHubStrategy            
=============================================
*/  
    passport.use('github', new GitHubStrategy(
        {
            clientID: 'Iv1.12ea9e284b4cd2fd',
            clientSecret: '11bb7e045227cf62f26c0b273e0ed9e4a7d7dfd2',
            callbackUrl: 'http://localhost:8080/api/sessions/githubcallback'
        }, async (accessToken, refreshToken, profile, done) => {
                console.log("Profile obtenido del usuario:");
                console.log(profile);
                try {
                    const user = await userModel.findOne({ email: profile._json.email });
                    console.log("Usuario encontrado para login:");
                    console.log(user);

                    if (!user) {
                        console.warn("User doesn't exists with username: " + profile._json.email);

                        let newUser = {
                            first_name: profile._json.name,
                            last_name: '',
                            age: 25,
                            email: profile._json.email,
                            password: '',
                            loggedBy: 'GitHub'
                        }
                        const result = await userModel.create(newUser)
                        return done(null, result)
                    } else {
                        //Si entramos por acá significa que el usuario ya existía.
                        return done(null, user)
                    }
                } catch (error) {
                    return done(error)
                }
            }
    ))



/*
=============================================
                Local-Passport            
=============================================
*/

    passport.use('register', new localStrategy(
        // passReqToCallback: para convertirlo en un callback de request, para asi poder iteracturar con la data que viene del cliente
        // usernameField: renombramos el username
        { passReqToCallback: true, usernameField: 'email' },

        // este seria nuestro callback donde hacemos todas las validaciones
        // done: seria el equivalente al next() y con este done le indicamos que terminamos X validacion.
        async (req, username, password, done) => {
            const { first_name, last_name, email, age } = req.body   
            try {
                    const exists = await userModel.findOne({ email })
                    if (exists) {
                        console.log("El usuario ya existe!!");
                        return done(null, false)
                    }
                    //  Si el user no existe en la DB  

                    // CREA EL CARRO                 
                    const cart = await carts.addCart();  

                    // OBTIENE LOS CARROS
                    const cart2 = await carts.getCarts(); 
                    let lastCart = "";

                    // OBTIENE EL ID DEL ULTIMO CARRO CREADO
                    if (cart2.length > 0) {
                        lastCart = cart2[cart2.length - 1]; 
                        console.log("ID del último carro agregado:", lastCart._id);
                    } else {
                        console.log("No hay carritos disponibles.");
                    }  

                    const user = {
                    first_name,
                    last_name,
                    email,
                    age,
                    cart: lastCart._id,                    
                    password: createHash(password)                    
                    }

                    const result = await userModel.create(user);                    
                    return done(null, result)
                } catch (error) {
                    return done("Error registrando el usuario: " + error)
                }
        }
    ))
     
    



    passport.use('login', new localStrategy(
        { passReqToCallback: true, usernameField: 'email' },
        async (req, username, password, done) => {
            try {
                const user = await userModel.findOne({ email: username })

                console.log("no existe un usuario con ese email")
                //console.log("Usuario encontrado para login:");
                console.log(user);

                if (!user) {
                    console.log("no existe el usuario")
                    console.warn("Invalid credentials for user: " + username);
                    return done(null, false)
                }

                // Validamos usando Bycrypt credenciales del usuario
                if (!isValidPassword(user, password)) {

                    console.log("El usuario existe pero la contraseña es incorrecta")
                    console.warn("Invalid credentials for user: " + username);
                    return done(null, false)
                }
                // req.session.user = {
                //     name: `${user.first_name} ${user.last_name}`,
                //     email: user.email,
                //     age: user.age
                // }

                return done(null, user)
            } catch (error) {
                return done(error)
            }
        }
    ))






/*
=============================================
Funciones de Serializacion y Desserializacion           
=============================================
*/
    passport.serializeUser((user, done) => {
        done(null, user._id);
    });

    passport.deserializeUser(async (id, done) => {
        try {
            let user = await userModel.findById(id);
            done(null, user);
        } catch (error) {
            console.error("Error deserializando el usuario: " + error);
        }
    });
};





const cookieExtractor = req => {
    let token = null;
    console.log("Entrando a Cookie Extractor");
    if (req && req.cookies) { //Validamos que exista el request y las cookies.
        console.log("Cookies presentes: ");
        console.log(req.cookies);
        token = req.cookies['jwtCookieToken'];
        console.log("Token obtenido desde Cookie:");
        console.log(token);
    }
    return token;
};

export default initializePassport;