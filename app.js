//jshint esversion:6
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
const GoogleStrategy = require('passport-google-oauth20').Strategy;



const app = express();


app.set("view engine","ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended : true}));

app.use(session({
  secret : process.env.YOUR_SESSION_SECRET,
  name : process.env.YOUR_COOKIE_NAME,
  resave : false,
  saveUninitialized : false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",{
  useNewUrlParser : true,
  useUnifiedTopology : true
});

const userSchema = new mongoose.Schema({
  email : String,
  password : String,
  googleId : String,
  secret : []
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User",userSchema);

passport.use(User.createStrategy());


passport.serializeUser(function(user,done){
  done(null,user.id);
});

passport.deserializeUser(function(id,done){
  User.findById(id,function(err,user){
    done(err,user)
  })
})


passport.use(new GoogleStrategy({
  clientID : process.env.YOUR_CLIENT_ID,
  clientSecret : process.env.YOUR_CLIENT_SECRET,
  callbackURL : process.env.YOUR_GOOGLE_CALLBACK
}, function(accessToken,refreshToken,profile,cb){
  User.findOrCreate({googleId : profile.id} , function(err,user){
   return  cb(err,user);
  })
}))


app.get("/auth/google",
passport.authenticate("google",{scope : ["profile"]})
);

app.get("/auth/google/secrets",
passport.authenticate("google",{failureRedirect : "/login"}),function(req,res){
  res.redirect("/secrets");
})




app.get("/",function(req,res){
  res.render("home");
});

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.get("/secrets",function(req,res){
  User.find({secret : {$ne : null}},function(err,foundUsers){
    if(foundUsers){
      res.render("secrets",{usersWithSecret : foundUsers});
  }else{
    console.log(err);
  }


  })
})

app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
})

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
})

app.post("/register",function(req,res){
  User.register({username : req.body.username},req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      })
    }
  })
});

app.post("/login",function(req,res){
  const user = new User({
    username : req.body.username,
    password : req.body.password
  });
  req.login(user,function(err){
    if(err){
      console.log(err);
      res.redirect("/login");
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      })
    }
  })
  });

  app.post("/submit",function(req,res){
    const submittedSecret = req.body.secret;
    User.findById(req.user.id,function(err,user){
      if(err){
        console.log(err);
      }else{
        if(user){
          user.secret.push(submittedSecret);
          user.save(function(){
            res.redirect("/secrets");
          })

        }
      }
    })
  })

app.listen(3000,function(){
  console.log("Server started at port 3000");
});
