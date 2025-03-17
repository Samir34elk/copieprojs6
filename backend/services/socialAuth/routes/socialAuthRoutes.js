const express = require("express");
const passport = require("passport");
const FacebookStrategy = require("passport-facebook").Strategy;
const TwitterStrategy = require("passport-twitter").Strategy;
const User = require("../models/User"); // Importez votre modèle User
const SocialAuth = require("../models/SocialAuth"); // Importez votre modèle SocialAuth
const router = express.Router();

// Middleware pour protéger les routes
const authMiddleware = require("../middlewares/authMiddleware");

// Facebook OAuth
router.get("/connect/facebook", passport.authenticate("facebook", {
    scope: ["email", "public_profile", "pages_read_user_content", "read_insights", "pages_show_list", "business_management", "pages_read_engagement", "pages_manage_metadata", "pages_manage_posts", "instagram_basic", "instagram_content_publish", "ads_management", "instagram_manage_insights", "ads_read"]
}));

router.get("/connect/facebook/callback", passport.authenticate("facebook", { failureRedirect: "/login" }),
    async (req, res) => {
        const { id, accessToken } = req.user;
        const userId = req.query.user_id; // Récupérer l'ID de l'utilisateur connecté depuis l'URL

        if (!userId) {
            return res.status(400).json({ error: "user_id manquant !" });
        }

        try {
            // Enregistrer ou mettre à jour le token en base
            await SocialAuth.findOneAndUpdate(
                { user: userId, provider: "facebook" },
                { accessToken },
                { upsert: true, new: true }
            );

            res.send("<script>window.close();</script>"); // Ferme la popup après succès
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: "Erreur lors de l'enregistrement du token" });
        }
    }
);

// Twitter OAuth
router.get("/connect/twitter", passport.authenticate("twitter"));

router.get(
    "/connect/twitter/callback",
    passport.authenticate("twitter", { failureRedirect: "/login" }),
    async (req, res) => {
        const { id, accessToken } = req.user;
        const userId = req.query.user_id; // Récupérer l'ID de l'utilisateur connecté depuis l'URL

        if (!userId) {
            return res.status(400).json({ error: "user_id manquant !" });
        }

        try {
            // Enregistrer ou mettre à jour le token en base
            await SocialAuth.findOneAndUpdate(
                { user: userId, provider: "twitter" },
                { accessToken },
                { upsert: true, new: true }
            );

            res.send("<script>window.close();</script>"); // Ferme la popup après succès
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: "Erreur lors de l'enregistrement du token" });
        }
    }
);

// Configuration des stratégies Passport
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

            let user = await User.findOne({ facebookId: profile.id });
            if (!user) {
                user = new User({
                    facebookId: profile.id,
                    email: profile.emails ? profile.emails[0].value : "",
                    name: profile.name.givenName + " " + profile.name.familyName
                });
                await user.save();
            }

            return done(null, { id: user.id, accessToken });
        } catch (err) {
            return done(err, null);
        }
    }
));

passport.use(new TwitterStrategy({
    consumerKey: process.env.TWITTER_KEY,
    consumerSecret: process.env.TWITTER_SECRET,
    callbackURL: process.env.PROXY_GATEWAY + "/api/socialauth/twitter/callback"
},
    async (token, tokenSecret, profile, cb) => {
        try {
            let user = await User.findOne({ twitterId: profile.id });
            if (!user) {
                user = new User({
                    twitterId: profile.id,
                    username: profile.username,
                    displayName: profile.displayName
                });
                await user.save();
            }
            cb(null, user);
        } catch (err) {
            cb(err, null);
        }
    }
));

// Sérialisation et désérialisation de l'utilisateur
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    const user = await User.findById(id);
    done(null, user);
});

module.exports = router;
