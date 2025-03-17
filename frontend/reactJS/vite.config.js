import {defineConfig} from 'vite'
import react from '@vitejs/plugin-react'
import Pages from 'vite-plugin-pages'
import * as fs from "node:fs";

export default defineConfig({
    plugins: [
        react(),
        Pages({dirs: 'src/pages'}),
    ],
    build: {
        target: 'esnext',

    },
    server: {
        proxy: {
            '/api': "https://localhost:3000",
        },

        host: "localhost",
        // Change si besoin

    },
})
