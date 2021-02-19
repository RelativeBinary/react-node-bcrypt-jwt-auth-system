//setup commands
//run: npm init
//make an index.js file
//apply all the following details below
//run: npm install
//run: node index.js
const express = require('express'); 
const mysql = require('mysql');
const cors = require('cors');

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');

const bcrypt = require('bcrypt');
const saltRounds = 10;

const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors({
    origin: ['http://localhost:3000'],
    methods: ["GET", "POST"],
    credentials: true //enables the cookie
}));
app.use(cookieParser());
app.use(bodyParser.urlencoded({extended: true}))

app.use(session({
    key: "userId",
    secret: "somethingYoullNeverKnow",
    resave: false,
    saveUninitialized: false, 
    cookie: {
        expires: 60 * 60 * 24, 
    }
}))

const db = mysql.createConnection({
    user: 'root',
    host: 'localhost',
    password: 'Pi399879',
    database: 'FakeAuthDB',
})

app.post("/register", (axiosRequest, axiosResponse) => {

    const username = axiosRequest.body.username;
    const password = axiosRequest.body.password;
    //check if user already exists
    db.query("SELECT * FROM users WHERE username = ?;", username, 
    (queryError, queryResult) => {
        if (queryResult.length > 0) {
            console.log("Invalid username!");    
            axiosResponse.send({message:"Invalid username!"})
        } else {
            //create new user
            bcrypt.hash(password, saltRounds, (bcryptError, bcryptHash) => {
                db.query("INSERT INTO users (username, password) VALUES (?, ?)", 
                [username, bcryptHash],
                (queryError, queryResult) => {
                    if(queryError) {
                        console.log(queryError);
                        axiosResponse.send({message: queryError});
                    } else {
                        console.log(queryResult);
                        axiosResponse.send({message: queryResult});
                    }
                });
            });
        }
    });
});

const verifyJWT = (req, res, next) => {
    //passing tokens through the headers not through the request is ideal
    const token = req.body.headers["x-access-token"];
    //console.log(req);
    console.log("token being verified is: " + req.body.headers["x-access-token"]);
    if (!token) {
        res.send("NO TOKEN FOUND");
    } else {
        //verify the token
        
        jwt.verify(token, "jwtSecretOOO", (err, decoded) => {
            if(err) {
                console.log("VERIFICATION FAILED " + err);
                res.json({authorized: false, message: "AUTHENTICATION FAILED", err: err})
            } else {
                //save the token id
                console.log("VERIFY SUCCESS")
                req.userId = decoded.id;
                next();
            }
        })
    }
}

//check if user is authenticated
app.post('/isUserAuthenticated',verifyJWT, (req, res) => {
    res.send("AUTHENTICATION SUCCESSFUL");
    // this means you are a user who is authenticated and able to make API reqs with 
    // the right token which enables us to safely check if the user is in the right
    // session 
})

//will set the session if it exists
app.get("/login", (req, res) => {
    if (req.session.user) {
        //note returning user information should not be done in actual practice
        //this is just to demonstraight communications is working
        res.send({ loggedIn: true, user: req.session.user });
    } else {
        res.send({ loggedIn: false, message: "session cookie empty at the moment 🍪"})
    }
})

app.post("/login", (axiosRequest, axiosResponse) => {
    const username = axiosRequest.body.username;
    const password = axiosRequest.body.password;

    db.query("SELECT * FROM users WHERE username = ?;", 
    username,
    (queryError, queryResult) => {
        if(queryError){
            axiosResponse.send({err: queryError});
        }
        //check if password is same as hash
        if (queryResult.length > 0) {
            bcrypt.compare(password, queryResult[0].password, (compareError, compareResults) => {
                if(compareResults) {
                    //console.log('session data')
                    //console.log(axiosRequest.session.user);
                    //console.log('login success');
                    
                    const id = queryResult[0].id;

                    //creating the token
                    //youd normally have a .env file for this 
                    const token = jwt.sign({id}, "jwtSecretOOO", {
                        expiresIn: 300, //5mins
                    });
                    axiosRequest.session.user = queryResult;
                    axiosResponse.json({authorized: true, token: token, result: queryResult})
                } else {
                    console.log('login failure');
                    axiosResponse.json({authorized: false, message: "wrong username pass combo"})
                }
            });
        } else {
            console.log('user not found');
            axiosResponse.json({authorized: false, message: "no user exists"})
        }
    })
});

app.listen(3001, () => {
    console.log('server running');
})