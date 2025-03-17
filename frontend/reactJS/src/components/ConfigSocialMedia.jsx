import React, {useState} from "react";
import {FaFacebook, FaTwitter, FaInstagram} from 'react-icons/fa';
import SocialButton from "./SocialButton"; // Assurez-vous que SocialButton est bien un composant réutilisable qui accepte un logo

function ConfigSocialMedia() {
    const [error, setError] = useState(null);

    const deconnexion = () => {
        localStorage.removeItem("token");
        localStorage.removeItem("user_id");
        window.location.reload();
    };

    const handleLinkSocialMedia = async (network) => {
        try {
            const user_id = localStorage.getItem("user_id"); // Récupération du user_id stocké

            if (!user_id) {
                throw new Error("Utilisateur non identifié !");
            }

            let authUrl = `/api/socialauth/connect/${network}?user_id=${user_id}`;

            const width = 600;
            const height = 700;
            const left = (window.screen.width - width) / 2;
            const top = (window.screen.height - height) / 2;

            const authWindow = window.open(
                authUrl,
                "_blank",
                `width=${width},height=${height},top=${top},left=${left}`
            );

            if (!authWindow) {
                throw new Error("Échec de l'ouverture de la fenêtre d'authentification.");
            }

            const checkPopupClosed = setInterval(() => {
                if (authWindow.closed) {
                    clearInterval(checkPopupClosed);
                    console.log("Fenêtre d'authentification fermée. Rafraîchissement...");
                    window.location.reload();
                }
            }, 1000);
        } catch (err) {
            setError("Une erreur est survenue lors de la connexion au réseau social.");
        }
    };

    return (
        <div>
            <h2 className="text-2xl font-bold text-center text-gray-700 mb-6">Configurer vos réseaux sociaux</h2>
            <div className="space-y-4">
                {/* Assurez-vous que le logo que vous passez est le bon icône */}
                <SocialButton
                    handleClick={() => handleLinkSocialMedia('facebook')}
                    logo={<FaFacebook size={20}/>}
                    network="facebook"
                />
                <SocialButton
                    handleClick={() => handleLinkSocialMedia('twitter')}
                    logo={<FaTwitter size={30}/>}
                    network="twitter"
                />
                <SocialButton
                    handleClick={() => handleLinkSocialMedia('instagram')}
                    logo={<FaInstagram size={30}/>}
                    network="instagram"
                />
            </div>
            {error && <p className="text-red-500 text-sm mt-2 text-center">{error}</p>}
            <button
                className="w-full bg-gray-400 text-white py-3 mt-6 rounded hover:bg-red-600 transition"
                onClick={deconnexion}>Déconnexion
            </button>
        </div>
    );
}

export default ConfigSocialMedia;