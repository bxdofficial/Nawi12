import { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useAuth } from '../../contexts/AuthContext'
import { useTheme } from '../../contexts/ThemeContext'
import { 
  Bars3Icon, 
  XMarkIcon, 
  UserCircleIcon,
  ArrowRightOnRectangleIcon,
  Cog6ToothIcon,
  SunIcon,
  MoonIcon
} from '@heroicons/react/24/outline'

const Navbar = () => {
  const [isOpen, setIsOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)
  const location = useLocation()
  const { user, logout, isAdmin } = useAuth()
  const { isDarkMode, toggleTheme } = useTheme()

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20)
    }
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  const navLinks = [
    { name: 'Home', path: '/' },
    { name: 'About', path: '/about' },
    { name: 'Services', path: '/services' },
    { name: 'Portfolio', path: '/portfolio' },
    { name: 'Contact', path: '/contact' },
  ]

  const isActive = (path) => location.pathname === path

  return (
    <motion.nav
      initial={{ y: -100 }}
      animate={{ y: 0 }}
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled ? 'glass-effect shadow-lg' : 'bg-transparent'
      }`}
    >
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-20">
          {/* Logo */}
          <Link
            to="/"
            className="flex items-center space-x-3 group"
          >
            <motion.div
              whileHover={{ scale: 1.05, rotate: 360 }}
              transition={{ duration: 0.5 }}
              className="w-14 h-14 rounded-xl flex items-center justify-center shadow-md overflow-hidden"
            >
              <img src="/nawi-logo.png" alt="Nawi Logo" className="w-12 h-12 object-contain" />
            </motion.div>
            <div className="ml-2">
              <img src="/nawi-text-logo.png" alt="Nawi" className="h-8 md:h-10 object-contain" />
            </div>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            {navLinks.map((link) => (
              <Link
                key={link.path}
                to={link.path}
                className={`relative font-medium transition-colors duration-300 ${
                  isActive(link.path)
                    ? isDarkMode ? 'text-nawi-blue' : 'text-nawi-sky'
                    : isDarkMode ? 'text-gray-300 hover:text-white' : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                {link.name}
                {isActive(link.path) && (
                  <motion.div
                    layoutId="navbar-indicator"
                    className={`absolute -bottom-2 left-0 right-0 h-0.5 ${
                      isDarkMode 
                        ? 'bg-gradient-to-r from-nawi-blue to-nawi-purple'
                        : 'bg-gradient-to-r from-nawi-sky to-nawi-cyan'
                    }`}
                  />
                )}
              </Link>
            ))}

            {/* Theme Toggle */}
            <motion.button
              onClick={toggleTheme}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="p-2 rounded-full glass-effect hover:bg-white/10 transition-colors"
              title={isDarkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            >
              {isDarkMode ? (
                <SunIcon className="w-6 h-6 text-nawi-sky" />
              ) : (
                <MoonIcon className="w-6 h-6 text-nawi-blue" />
              )}
            </motion.button>

            {/* User Menu */}
            {user ? (
              <div className="flex items-center space-x-4 ml-8">
                {isAdmin && (
                  <Link
                    to="/admin"
                    className="p-2 rounded-full hover:bg-white/10 transition-colors"
                    title="Admin Dashboard"
                  >
                    <Cog6ToothIcon className="w-6 h-6 text-nawi-purple" />
                  </Link>
                )}
                <Link
                  to="/dashboard"
                  className="p-2 rounded-full hover:bg-white/10 transition-colors"
                  title="Dashboard"
                >
                  <UserCircleIcon className="w-6 h-6" />
                </Link>
                <button
                  onClick={logout}
                  className="p-2 rounded-full hover:bg-white/10 transition-colors"
                  title="Logout"
                >
                  <ArrowRightOnRectangleIcon className="w-6 h-6 text-red-400" />
                </button>
              </div>
            ) : (
              <div className="flex items-center space-x-4 ml-8">
                <Link
                  to="/login"
                  className="px-6 py-2 text-white hover:text-nawi-blue transition-colors"
                >
                  Login
                </Link>
                <Link
                  to="/register"
                  className="button-primary text-sm"
                >
                  Get Started
                </Link>
              </div>
            )}
          </div>

          {/* Mobile Menu Toggle */}
          <button
            onClick={() => setIsOpen(!isOpen)}
            className="md:hidden p-2 rounded-lg hover:bg-white/10 transition-colors"
          >
            {isOpen ? (
              <XMarkIcon className="w-6 h-6" />
            ) : (
              <Bars3Icon className="w-6 h-6" />
            )}
          </button>
        </div>
      </div>

      {/* Mobile Menu */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="md:hidden glass-effect border-t border-white/10"
          >
            <div className="container mx-auto px-4 py-4">
              {navLinks.map((link) => (
                <Link
                  key={link.path}
                  to={link.path}
                  onClick={() => setIsOpen(false)}
                  className={`block py-3 px-4 rounded-lg transition-colors ${
                    isActive(link.path)
                      ? 'bg-gradient-to-r from-nawi-blue/20 to-nawi-purple/20 text-white'
                      : 'text-gray-300 hover:bg-white/5 hover:text-white'
                  }`}
                >
                  {link.name}
                </Link>
              ))}

              <div className="mt-4 pt-4 border-t border-white/10">
                {user ? (
                  <div className="space-y-2">
                    {isAdmin && (
                      <Link
                        to="/admin"
                        onClick={() => setIsOpen(false)}
                        className="block py-3 px-4 rounded-lg text-nawi-purple hover:bg-white/5"
                      >
                        Admin Dashboard
                      </Link>
                    )}
                    <Link
                      to="/dashboard"
                      onClick={() => setIsOpen(false)}
                      className="block py-3 px-4 rounded-lg hover:bg-white/5"
                    >
                      Dashboard
                    </Link>
                    <button
                      onClick={() => {
                        logout()
                        setIsOpen(false)
                      }}
                      className="w-full text-left py-3 px-4 rounded-lg text-red-400 hover:bg-white/5"
                    >
                      Logout
                    </button>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <Link
                      to="/login"
                      onClick={() => setIsOpen(false)}
                      className="block py-3 px-4 rounded-lg hover:bg-white/5"
                    >
                      Login
                    </Link>
                    <Link
                      to="/register"
                      onClick={() => setIsOpen(false)}
                      className="block text-center button-primary"
                    >
                      Get Started
                    </Link>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.nav>
  )
}

export default Navbar