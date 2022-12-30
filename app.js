/////////IMPORTING THE MODULES/////////
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

/////////CONFIGURE EXPRESS APP AND MIDDLEWARE/////////
const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set('trust proxy', 1) // trust first proxy
app.use(session({
  secret: "our little secret",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

///////// LOCAL DEVELOPMENT: CONNECTION TO MONGODB DATABASE/////////
mongoose.set("strictQuery", false);
// mongoose.connect("mongodb://127.0.0.1:27017/userDB");

///////// CONNECTION TO MONGO ATLAS CLUSTER/////////
mongoose.connect("mongodb+srv://"+process.env.ATLAS_ADMIN_USERNAME +":"+ process.env.ATLAS_ADMIN_PASSWORD+"@cluster0.khvebqd.mongodb.net/userDB");

/////////USER SCHEMA AND COLLECTION/MODEL/////////
const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId: String,
    secret: Array
  });

///////// PLUGIN PASSPORT-LOCAL-MONGOOSE INTO THE SCHEMA/////////
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User",userSchema);

///////// SIMPLIFIED PASSPORT/PASSPORT-LOCAL CONFIGURATION / GOOGLE SESSIONS///////// 
passport.use(User.createStrategy()); 
//creates cookie with unique user id
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
//deletes cookie with the unique user id
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

/////////GOOGLE AUTHENTICATION CONFIGURE STRATEGY/////////

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL,
    userProfileURL: process.env.USER_PROFILE_URL
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

/////////GOOGLE ROUTE TO AUTHENTICATE REQUESTS/////////
app.get('/auth/google',
passport.authenticate('google',{scope:["profile"]})
);
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });
  

/////////HOME ROUTE GET REQUESTS////////
app.get("/",function(req,res){
    res.render("home")
});

/////////REGISTER ROUTE GET AND POST REQUESTS////////
app.route("/register")
.get(function(req,res){
    res.render("register")
})
.post(function(req,res){
    User.register({username:req.body.username}, req.body.password,function(err,user){
        if(err){
            console.log(err);
         res.redirect("/register");
        }else{
        passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
        });
        };
    });
});

/////////LOGIN ROUTE GET AND POST REQUESTS////////
app.route("/login")
.get(function(req,res){
    res.render("login")
})
.post(function(req,res){
    const user = new User({
     username: req.body.username,
     password: req.body.password
    });
    req.login(user,function(err){
        if(err){
            console.log(err);
        }else{
        passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
            });
        };
    });
});

/////////SUBMIT ROUTE GET AND POST REQUESTS////////
app.route("/submit")
.get(function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
  })
.post(function(req,res){
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, function(err, foundUser){
        if (err) {
          console.log(err);
        } else {
          if (foundUser) {
            foundUser.secret = submittedSecret;
            //allow one user submit several secrets
            // foundUser.secret.push(submittedSecret);
            foundUser.save(function(){
              res.redirect("/secrets");
            });
          
          }
        }
      });
});

/////////SECRETS ROUTE GET AND POST REQUESTS////////
app.route("/secrets")
.get(function(req,res){
   User.find({"secret":{$ne:null}},function(err,foundUsers){
    if(err){
        console.log(err);
    }else{
        if(foundUsers){
            res.render("secrets",{usersWithSecrets:foundUsers});
        }
    }
   });
});

//////////////LOGOUT ROUTE//////////////////////
app.get('/logout', function(req, res) {
    req.logout(function(err) {
      if (err) { 
        return (err); 
        }
      res.redirect('/');
    });
  });

/////////////STARTING THE SERVER//////////////////////
let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}
app.listen(port, function() {
  console.log("Server started succesfully");
});
