const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({error: "Accès refusé"});
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Ajoute l'utilisateur décodé à `req`
        next();
    } catch (err) {
        res.status(403).json({error: "Token invalide"});
    }
};
