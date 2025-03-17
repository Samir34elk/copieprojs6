const express = require("express");
const passport = require("passport");
const FacebookStrategy = require("passport-facebook").Strategy;
const TwitterStrategy = require("passport-twitter").Strategy;
const User = require("../../users/models/User"); // Modèle User
const SocialAuth = require("../models/SocialAuth"); // Modèle SocialAuth
const router = express.Router();

// Middleware pour protéger les routes
const authMiddleware = require("../middlewares/authMiddleware");

// Facebook OAuth
router.get("/connect/facebook", passport.authenticate("facebook", {
    scope: ["email", "public_profile", "pages_read_user_content", "read_insights", "pages_show_list", "business_management", "pages_read_engagement", "pages_manage_metadata", "pages_manage_posts", "instagram_basic", "instagram_content_publish", "ads_management", "instagram_manage_insights", "ads_read"]
}));

router.get("/connect/facebook/callback", passport.authenticate("facebook", { failureRedirect: "/login" }),
    async (req, res) => {
        const { id, accessToken } = req.user; // Informations renvoyées par Facebook
        const userId = req.query.user_id; // ID de l'utilisateur connecté dans votre application

        if (!userId) {
            return res.status(400).json({ error: "user_id manquant !" });
        }

        try {
            // Enregistrer ou mettre à jour la configuration Facebook dans SocialAuth
            await SocialAuth.findOneAndUpdate(
                { user: userId, provider: "facebook" }, // Critères de recherche
                {
                    providerId: id, // Facebook ID
                    accessToken,
                    email: req.user.email, // Optionnel
                    name: req.user.name // Optionnel
                },
                { upsert: true, new: true } // Crée une entrée si elle n'existe pas
            );

            res.send("<script>window.close();</script>"); // Ferme la popup après succès
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: "Erreur lors de l'enregistrement de la configuration Facebook" });
        }
    }
);

// Twitter OAuth
router.get("/connect/twitter", passport.authenticate("twitter"));

router.get(
    "/connect/twitter/callback",
    passport.authenticate("twitter", { failureRedirect: "/login" }),
    async (req, res) => {
        const { id, accessToken } = req.user; // Informations renvoyées par Twitter
        const userId = req.query.user_id; // ID de l'utilisateur connecté dans votre application

        if (!userId) {
            return res.status(400).json({ error: "user_id manquant !" });
        }

        try {
            // Enregistrer ou mettre à jour la configuration Twitter dans SocialAuth
            await SocialAuth.findOneAndUpdate(
                { user: userId, provider: "twitter" }, // Critères de recherche
                {
                    providerId: id, // Twitter ID
                    accessToken,
                    username: req.user.username, // Optionnel
                    displayName: req.user.displayName // Optionnel
                },
                { upsert: true, new: true } // Crée une entrée si elle n'existe pas
            );

            res.send("<script>window.close();</script>"); // Ferme la popup après succès
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: "Erreur lors de l'enregistrement de la configuration Twitter" });
        }
    }
);

// Configuration des stratégies Passport
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: process.env.PROXY_GATEWAY + "/api/socialauth/connect/facebook/callback",
    profileFields: ["id", "emails", "name"],
    passReqToCallback: true // Passe l'objet `req` au callback
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

            // Renvoyer les informations nécessaires pour SocialAuth
            return done(null, {
                id: profile.id, // Facebook ID
                accessToken,
                email: profile.emails ? profile.emails[0].value : null,
                name: profile.name.givenName + " " + profile.name.familyName
            });
        } catch (err) {
            return done(err, null);
        }
    }
));

passport.use(new TwitterStrategy({
    consumerKey: process.env.TWITTER_KEY,
    consumerSecret: process.env.TWITTER_SECRET,
    callbackURL: process.env.PROXY_GATEWAY + "/api/socialauth/twitter/callback",
    passReqToCallback: true // Passe l'objet `req` au callback
},
    async (req, token, tokenSecret, profile, done) => {
        try {
            // Renvoyer les informations nécessaires pour SocialAuth
            return done(null, {
                id: profile.id, // Twitter ID
                accessToken: token,
                username: profile.username,
                displayName: profile.displayName
            });
        } catch (err) {
            return done(err, null);
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
