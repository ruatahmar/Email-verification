import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// https://vite.dev/config/
export default defineConfig({
	plugins: [react(), tailwindcss()],
	build: {
		outDir: '../backend/public',
		emptyOutDir: true,
		rollupOptions: {
			output: {
				manualChunks: {
					// Vendor chunk for React and related libraries
					'react-vendor': ['react', 'react-dom', 'react-router-dom'],

					// UI libraries chunk
					'ui-vendor': ['lucide-react', 'framer-motion', 'react-toastify'],

					// Form libraries chunk
					'form-vendor': ['react-hook-form', '@hookform/resolvers', 'zod'],

					// HTTP and utilities chunk
					'http-vendor': ['axios'],
				},
			},
		},
		chunkSizeWarningLimit: 600,
	},
});
