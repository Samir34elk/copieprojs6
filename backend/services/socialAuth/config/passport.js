const passport = require("passport");
const FacebookStrategy = require("passport-facebook").Strategy;
const TwitterStrategy = require("passport-twitter").Strategy;

const User = require("../../users/models/User");

passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_CLIENT_ID,
        clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
        callbackURL: process.env.PROXY_GATEWAY + "/api/socialauth/connect/facebook/callback",
        profileFields: ["id", "emails", "name"],
        passReqToCallback: true // Ajoutez cette option pour passer l'objet `req` au callback
    },
    async (req, accessToken, refreshToken, profile, done) => {
        try {
            // Log l'adresse IP et l'origine de la requête
            const clientIP = req.ip || req.connection.remoteAddress;
            const origin = req.headers.origin || req.headers.referer;
            console.log("Requête reçue de :", {
                ip: clientIP,
                origin: origin
            });

            let user = await User.findOne({facebookId: profile.id});
                console.log("je suis la");
            if (!user) {
                user = new User({
                    facebookId: profile.id,
                    email: profile.emails ? profile.emails[0].value : "",
                    name: profile.name.givenName + " " + profile.name.familyName
                });
                await user.save();
            }

            return done(null, {id: user.id, accessToken});
        } catch (err) {
            return done(err, null);
        }
    }
)); 

passport.use(new TwitterStrategy({
        consumerKey: process.env.TWITTER_KEY,
        consumerSecret: process.env.TWITTER_SECRET,
        callbackURL: process.env.PROXY_GATEWAY + "api/socialauth/twitter/callback"
    },
    function (token, tokenSecret, profile, cb) {
        User.findOrCreate({twitterId: profile.id}, function (err, user) {
            return cb(err, user);
        });
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    const user = await User.findById(id);
    done(null, user);
});

