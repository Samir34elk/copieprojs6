const express = require("express");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const SocialAuth = require("../models/SocialAuth");
const router = express.Router();

// Middleware pour protéger les routes
const authMiddleware = require("../middlewares/authMiddleware");

// Facebook OAuth
router.get("/connect/facebook", passport.authenticate("facebook", {scope: ["email,public_profile,pages_read_user_content,read_insights,pages_show_list,business_management,pages_read_engagement,pages_manage_metadata,pages_manage_posts,instagram_basic,instagram_content_publish,ads_management,instagram_manage_insights,ads_management,ads_read,pages_manage_posts,pages_read_user_content,read_insights,pages_show_list,business_management,pages_read_engagement,pages_manage_metadata,pages_manage_posts,instagram_basic,instagram_content_publish,ads_management,instagram_manage_insights,ads_management,ads_read,pages_manage_posts,pages_read_user_content"]}));

router.get("/connect/facebook/callback", passport.authenticate("facebook", {failureRedirect: "/login"}),
    async (req, res) => {
        const {id, accessToken} = req.user;
        const userId = req.query.user_id; // Récupérer l'ID de l'utilisateur connecté depuis l'URL

        if (!userId) {
            return res.status(400).json({error: "user_id manquant !"});
        }

        try {
            // Enregistrer ou mettre à jour le token en base
            await SocialAuth.findOneAndUpdate(
                {user: userId, provider: "facebook"},
                {accessToken},
                {upsert: true, new: true}
            );

            res.send("<script>window.close();</script>"); // Ferme la popup après succès
        } catch (err) {
            console.error(err);
            res.status(500).json({error: "Erreur lors de l'enregistrement du token"});
        }
    }
);

// Twitter OAuth
router.get("/connect/twitter", passport.authenticate("twitter"));

router.get(
    "/connect/twitter/callback",
    passport.authenticate("twitter", {failureRedirect: "/login"}),
    async (req, res) => {
        const {id, accessToken} = req.user;
        const userId = req.query.user_id; // Récupérer l'ID de l'utilisateur connecté depuis l'URL

        if (!userId) {
            return res.status(400).json({error: "user_id manquant !"});
        }

        try {
            // Enregistrer ou mettre à jour le token en base
            await SocialAuth.findOneAndUpdate(
                {user: userId, provider: "twitter"},
                {accessToken},
                {upsert: true, new: true}
            );

            res.send("<script>window.close();</script>"); // Ferme la popup après succès
        } catch (err) {
            console.error(err);
            res.status(500).json({error: "Erreur lors de l'enregistrement du token"});
        }
    }
);

module.exports = router;
