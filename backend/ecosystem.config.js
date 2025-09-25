module.exports = {
  apps: [{
    name: 'nawi-backend',
    script: 'python3',
    args: 'app.py',
    cwd: '/home/user/webapp/backend',
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'development'
    },
    env_production: {
      NODE_ENV: 'production'
    }
  }]
}
