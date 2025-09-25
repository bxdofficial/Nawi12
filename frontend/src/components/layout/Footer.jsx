import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { WhatsAppIcon, InstagramIcon, FacebookIcon, BehanceIcon, SocialIconWrapper } from '../ui/SocialIcons'
import {
  EnvelopeIcon,
  PhoneIcon,
  MapPinIcon,
} from '@heroicons/react/24/outline'

const Footer = () => {
  const currentYear = new Date().getFullYear()

  const socialLinks = [
    { name: 'WhatsApp', href: 'https://wa.me/201206315886', component: WhatsAppIcon },
    { name: 'Instagram', href: 'https://instagram.com/nawidesign', component: InstagramIcon },
    { name: 'Facebook', href: 'https://facebook.com/nawidesign', component: FacebookIcon },
    { name: 'Behance', href: 'https://behance.net/nawidesign', component: BehanceIcon },
  ]

  const quickLinks = [
    { name: 'Home', path: '/' },
    { name: 'About', path: '/about' },
    { name: 'Services', path: '/services' },
    { name: 'Portfolio', path: '/portfolio' },
    { name: 'Contact', path: '/contact' },
  ]

  const services = [
    { name: 'Logo Design', path: '/services#logo' },
    { name: 'Social Media', path: '/services#social' },
    { name: 'Brand Identity', path: '/services#brand' },
    { name: 'Print Design', path: '/services#print' },
  ]

  return (
    <footer className="relative bg-nawi-gray/50 backdrop-blur-lg border-t border-white/10 mt-20">
      <div className="container mx-auto px-4 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {/* Brand Section */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            viewport={{ once: true }}
          >
            <Link to="/" className="inline-flex items-center space-x-3 mb-4">
              <div className="w-12 h-12 rounded-xl flex items-center justify-center overflow-hidden">
                <img src="/nawi-logo.png" alt="Nawi Logo" className="w-10 h-10 object-contain" />
              </div>
              <div className="ml-2">
                <img src="/nawi-text-logo.png" alt="Nawi" className="h-10 md:h-12 object-contain" />
              </div>
            </Link>
            <p className="text-gray-400 mb-4">
              فريق التصميم اللي بيحوّل فكرتك لهوية مميزة
            </p>
            <div className="flex space-x-4">
              {socialLinks.map((social) => {
                const IconComponent = social.component
                return (
                  <motion.div
                    key={social.name}
                    whileHover={{ scale: 1.1, rotate: 5 }}
                    whileTap={{ scale: 0.9 }}
                  >
                    <SocialIconWrapper
                      href={social.href}
                      name={social.name}
                      className="w-10 h-10 flex items-center justify-center"
                    >
                      <IconComponent className="w-5 h-5" />
                    </SocialIconWrapper>
                  </motion.div>
                )
              })}
            </div>
          </motion.div>

          {/* Quick Links */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            viewport={{ once: true }}
          >
            <h4 className="text-lg font-semibold mb-4 gradient-text">Quick Links</h4>
            <ul className="space-y-2">
              {quickLinks.map((link) => (
                <li key={link.path}>
                  <Link
                    to={link.path}
                    className="text-gray-400 hover:text-white transition-colors inline-flex items-center group"
                  >
                    <span className="w-1 h-1 bg-nawi-blue rounded-full mr-2 group-hover:w-4 transition-all" />
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </motion.div>

          {/* Services */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            viewport={{ once: true }}
          >
            <h4 className="text-lg font-semibold mb-4 gradient-text">Our Services</h4>
            <ul className="space-y-2">
              {services.map((service) => (
                <li key={service.path}>
                  <Link
                    to={service.path}
                    className="text-gray-400 hover:text-white transition-colors inline-flex items-center group"
                  >
                    <span className="w-1 h-1 bg-nawi-purple rounded-full mr-2 group-hover:w-4 transition-all" />
                    {service.name}
                  </Link>
                </li>
              ))}
            </ul>
          </motion.div>

          {/* Contact Info */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            viewport={{ once: true }}
          >
            <h4 className="text-lg font-semibold mb-4 gradient-text">Contact Us</h4>
            <div className="space-y-3">
              <a
                href="mailto:nawycompany@gmail.com"
                className="flex items-center space-x-3 text-gray-400 hover:text-white transition-colors"
              >
                <EnvelopeIcon className="w-5 h-5 text-nawi-blue" />
                <span>nawycompany@gmail.com</span>
              </a>
              <a
                href="tel:+201206315886"
                className="flex items-center space-x-3 text-gray-400 hover:text-white transition-colors"
              >
                <PhoneIcon className="w-5 h-5 text-nawi-blue" />
                <span dir="ltr">+20 120 631 5886</span>
              </a>
              <div className="flex items-center space-x-3 text-gray-400">
                <MapPinIcon className="w-5 h-5 text-nawi-blue" />
                <span>Cairo, Egypt</span>
              </div>
            </div>

            {/* WhatsApp CTA */}
            <motion.a
              href="https://wa.me/201206315886"
              target="_blank"
              rel="noopener noreferrer"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="inline-flex items-center gap-2 mt-4 px-4 py-2 bg-green-500/20 hover:bg-green-500/30 
                       border border-green-500/50 rounded-full text-green-400 transition-all"
            >
              <span>💬</span>
              <span>Chat on WhatsApp</span>
            </motion.a>
          </motion.div>
        </div>

        {/* Bottom Bar */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.4 }}
          viewport={{ once: true }}
          className="mt-12 pt-8 border-t border-white/10"
        >
          <div className="flex flex-col md:flex-row justify-between items-center">
            <p className="text-gray-400 text-sm">
              © {currentYear} Nawi - ناوي. All rights reserved.
            </p>
            <div className="flex space-x-6 mt-4 md:mt-0">
              <Link to="/privacy" className="text-gray-400 hover:text-white text-sm transition-colors">
                Privacy Policy
              </Link>
              <Link to="/terms" className="text-gray-400 hover:text-white text-sm transition-colors">
                Terms of Service
              </Link>
            </div>
          </div>
          
          {/* Floating Gradient */}
          <div className="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-nawi-blue via-nawi-purple to-nawi-blue animate-gradient" />
        </motion.div>
      </div>
    </footer>
  )
}

export default Footer