export default {
    base: '/',
    server: {
        host: '0.0.0.0', // Listen on all IP addresses
        port: 5173,
        allowedHosts: ['pocketsoc.buru-paradise.ts.net'],
        proxy: {
            '/api': {
                target: 'http://localhost:3000',
                changeOrigin: true
            }
        }
    }
}
