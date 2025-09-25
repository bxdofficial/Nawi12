/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Enhanced light theme colors (sky blue theme)
        'nawi-sky': '#38BDF8',
        'nawi-sky-light': '#7DD3FC',
        'nawi-sky-lighter': '#BAE6FD',
        'nawi-sky-dark': '#0EA5E9',
        'nawi-cyan': '#06B6D4',
        'nawi-cyan-light': '#67E8F9',
        
        // Enhanced dark theme colors
        'nawi-blue': '#3B82F6',
        'nawi-blue-dark': '#1E40AF',
        'nawi-purple': '#6366F1',
        'nawi-purple-dark': '#4338CA',
        'nawi-indigo': '#4F46E5',
        'nawi-light-blue': '#60A5FA',
        'nawi-light-purple': '#8B5CF6',
        
        // Background colors
        'nawi-dark': '#0F172A',
        'nawi-dark-lighter': '#1E293B',
        'nawi-gray': '#334155',
        'nawi-gray-light': '#64748B',
        
        // Light theme backgrounds
        'nawi-light': '#F8FAFC',
        'nawi-light-gray': '#F1F5F9',
        'nawi-white': '#FFFFFF',
      },
      animation: {
        'glow': 'glow 2s ease-in-out infinite alternate',
        'glow-dark': 'glow-dark 2s ease-in-out infinite alternate',
        'float': 'float 6s ease-in-out infinite',
        'pulse-glow': 'pulse-glow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'pulse-glow-dark': 'pulse-glow-dark 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'gradient': 'gradient 8s ease infinite',
        'slide-up': 'slide-up 0.5s ease-out',
        'slide-down': 'slide-down 0.5s ease-out',
        'fade-in': 'fade-in 0.5s ease-out',
        'scale-in': 'scale-in 0.3s ease-out',
      },
      keyframes: {
        glow: {
          from: { textShadow: '0 0 10px #38BDF8, 0 0 20px #38BDF8, 0 0 30px #38BDF8' },
          to: { textShadow: '0 0 20px #06B6D4, 0 0 30px #06B6D4, 0 0 40px #06B6D4' }
        },
        'glow-dark': {
          from: { textShadow: '0 0 10px #3B82F6, 0 0 20px #3B82F6, 0 0 30px #3B82F6' },
          to: { textShadow: '0 0 20px #6366F1, 0 0 30px #6366F1, 0 0 40px #6366F1' }
        },
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-20px)' },
        },
        'pulse-glow': {
          '0%, 100%': {
            opacity: '1',
            boxShadow: '0 0 20px rgba(56, 189, 248, 0.5)',
          },
          '50%': {
            opacity: '.8',
            boxShadow: '0 0 40px rgba(6, 182, 212, 0.8)',
          },
        },
        'pulse-glow-dark': {
          '0%, 100%': {
            opacity: '1',
            boxShadow: '0 0 20px rgba(59, 130, 246, 0.5)',
          },
          '50%': {
            opacity: '.8',
            boxShadow: '0 0 40px rgba(99, 102, 241, 0.8)',
          },
        },
        gradient: {
          '0%, 100%': {
            'background-size': '200% 200%',
            'background-position': 'left center'
          },
          '50%': {
            'background-size': '200% 200%',
            'background-position': 'right center'
          },
        },
        'slide-up': {
          from: { transform: 'translateY(20px)', opacity: '0' },
          to: { transform: 'translateY(0)', opacity: '1' },
        },
        'slide-down': {
          from: { transform: 'translateY(-20px)', opacity: '0' },
          to: { transform: 'translateY(0)', opacity: '1' },
        },
        'fade-in': {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        'scale-in': {
          from: { transform: 'scale(0.9)', opacity: '0' },
          to: { transform: 'scale(1)', opacity: '1' },
        },
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic': 'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
      },
    },
  },
  plugins: [],
}