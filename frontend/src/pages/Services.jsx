import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { useInView } from 'react-intersection-observer'
import axios from 'axios'
import toast from 'react-hot-toast'
import { Link } from 'react-router-dom'
import {
  PaintBrushIcon,
  ShareIcon,
  SwatchIcon,
  PrinterIcon,
  SparklesIcon,
  CheckCircleIcon,
  ArrowRightIcon,
} from '@heroicons/react/24/outline'

const Services = () => {
  const [services, setServices] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedService, setSelectedService] = useState(null)
  const [titleRef, titleInView] = useInView({ threshold: 0.1, triggerOnce: true })

  useEffect(() => {
    fetchServices()
  }, [])

  const fetchServices = async () => {
    try {
      const response = await axios.get('/api/services')
      setServices(response.data)
    } catch (error) {
      toast.error('Failed to load services')
    } finally {
      setLoading(false)
    }
  }

  const getIcon = (iconName) => {
    const icons = {
      brush: <PaintBrushIcon className="w-8 h-8" />,
      share: <ShareIcon className="w-8 h-8" />,
      palette: <SwatchIcon className="w-8 h-8" />,
      print: <PrinterIcon className="w-8 h-8" />,
    }
    return icons[iconName] || <SparklesIcon className="w-8 h-8" />
  }

  const getGradient = (index) => {
    const gradients = [
      'from-blue-500 to-cyan-500',
      'from-purple-500 to-pink-500',
      'from-green-500 to-teal-500',
      'from-orange-500 to-red-500',
    ]
    return gradients[index % gradients.length]
  }

  const serviceFeatures = {
    'Logo Design': [
      '3 Initial Concepts',
      'Unlimited Revisions',
      'Vector Files (AI, EPS, SVG)',
      'Brand Guidelines',
      'Color Variations',
      'Black & White Version',
    ],
    'Social Media Design': [
      'Custom Templates',
      'Story & Post Designs',
      'Reels Cover Design',
      'Highlight Icons',
      'Content Calendar',
      'Platform Optimization',
    ],
    'Brand Identity': [
      'Logo Design',
      'Business Cards',
      'Letterhead & Envelope',
      'Brand Style Guide',
      'Color Palette',
      'Typography System',
    ],
    'Print Design': [
      'Business Cards',
      'Flyers & Brochures',
      'Posters & Banners',
      'Print-Ready Files',
      'Multiple Size Variations',
      'Packaging Design',
    ],
  }

  return (
    <div className="min-h-screen pt-32 pb-20">
      {/* Hero Section */}
      <section className="relative mb-20">
        <div className="container mx-auto px-4">
          <motion.div
            ref={titleRef}
            initial={{ opacity: 0, y: 50 }}
            animate={titleInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.8 }}
            className="text-center"
          >
            <motion.h1
              className="text-5xl md:text-6xl font-bold mb-6"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={titleInView ? { opacity: 1, scale: 1 } : {}}
              transition={{ duration: 0.5 }}
            >
              Our <span className="gradient-text">Services</span>
            </motion.h1>
            <motion.p
              className="text-xl text-gray-400 max-w-3xl mx-auto"
              initial={{ opacity: 0, y: 20 }}
              animate={titleInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              Professional design services tailored to elevate your brand and captivate your audience
            </motion.p>
          </motion.div>
        </div>

        {/* Animated Background Elements */}
        <motion.div
          animate={{
            rotate: [0, 360],
            scale: [1, 1.2, 1],
          }}
          transition={{
            duration: 20,
            repeat: Infinity,
            ease: 'linear',
          }}
          className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-br from-nawi-blue/10 to-nawi-purple/10 rounded-full blur-3xl"
        />
      </section>

      {/* Services Grid */}
      <section className="container mx-auto px-4">
        {loading ? (
          <div className="grid md:grid-cols-2 gap-8">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="glass-effect rounded-2xl p-8 animate-pulse">
                <div className="w-20 h-20 bg-gray-700 rounded-xl mb-6" />
                <div className="h-8 bg-gray-700 rounded mb-4 w-3/4" />
                <div className="h-4 bg-gray-700 rounded mb-2" />
                <div className="h-4 bg-gray-700 rounded w-5/6" />
              </div>
            ))}
          </div>
        ) : (
          <div className="grid md:grid-cols-2 gap-8">
            {services.map((service, index) => (
              <motion.div
                key={service.id}
                initial={{ opacity: 0, y: 50 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                viewport={{ once: true }}
                whileHover={{ y: -10 }}
                onClick={() => setSelectedService(service)}
                className="relative group cursor-pointer"
              >
                <div className="glass-effect rounded-2xl p-8 h-full hover:bg-white/10 transition-all duration-300">
                  {/* Icon */}
                  <motion.div
                    whileHover={{ rotate: 360, scale: 1.1 }}
                    transition={{ duration: 0.5 }}
                    className={`w-20 h-20 rounded-xl bg-gradient-to-br ${getGradient(index)} 
                               flex items-center justify-center mb-6 group-hover:shadow-2xl transition-all`}
                  >
                    {getIcon(service.icon)}
                  </motion.div>

                  {/* Title */}
                  <h3 className="text-2xl font-bold mb-2">{service.title}</h3>
                  <p className="text-gray-400 text-sm mb-4">{service.title_ar}</p>

                  {/* Description */}
                  <p className="text-gray-300 mb-6">{service.description}</p>

                  {/* Features */}
                  <div className="space-y-2 mb-6">
                    {serviceFeatures[service.title]?.slice(0, 3).map((feature, i) => (
                      <div key={i} className="flex items-center space-x-2">
                        <CheckCircleIcon className="w-5 h-5 text-green-500" />
                        <span className="text-sm text-gray-400">{feature}</span>
                      </div>
                    ))}
                  </div>

                  {/* Price Range */}
                  <div className="flex items-center justify-between">
                    <span className="text-2xl font-bold gradient-text">{service.price_range}</span>
                    <motion.button
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                      className="p-3 rounded-full bg-gradient-to-r from-nawi-blue to-nawi-purple 
                               group-hover:shadow-lg transition-all"
                    >
                      <ArrowRightIcon className="w-5 h-5" />
                    </motion.button>
                  </div>

                  {/* Hover Effect Border */}
                  <motion.div
                    className={`absolute inset-0 rounded-2xl bg-gradient-to-br ${getGradient(index)} 
                               opacity-0 group-hover:opacity-20 transition-opacity duration-300`}
                  />
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </section>

      {/* Service Modal */}
      {selectedService && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={() => setSelectedService(null)}
        >
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.8, opacity: 0 }}
            transition={{ type: 'spring', damping: 25 }}
            className="glass-effect rounded-3xl p-8 max-w-2xl w-full max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex justify-between items-start mb-6">
              <div>
                <h2 className="text-3xl font-bold mb-2">{selectedService.title}</h2>
                <p className="text-gray-400">{selectedService.title_ar}</p>
              </div>
              <button
                onClick={() => setSelectedService(null)}
                className="p-2 rounded-lg hover:bg-white/10 transition-colors"
              >
                ✕
              </button>
            </div>

            <p className="text-gray-300 mb-6">{selectedService.description_ar}</p>

            <h3 className="text-xl font-semibold mb-4 gradient-text">What's Included:</h3>
            <div className="grid md:grid-cols-2 gap-3 mb-8">
              {serviceFeatures[selectedService.title]?.map((feature, i) => (
                <div key={i} className="flex items-center space-x-3">
                  <CheckCircleIcon className="w-6 h-6 text-green-500 flex-shrink-0" />
                  <span className="text-gray-300">{feature}</span>
                </div>
              ))}
            </div>

            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Starting from</p>
                <p className="text-3xl font-bold gradient-text">{selectedService.price_range}</p>
              </div>
              <Link
                to="/contact"
                className="button-primary inline-flex items-center gap-2"
                onClick={() => setSelectedService(null)}
              >
                Request This Service
                <ArrowRightIcon className="w-5 h-5" />
              </Link>
            </div>
          </motion.div>
        </motion.div>
      )}

      {/* Process Section */}
      <section className="container mx-auto px-4 mt-20">
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <h2 className="text-4xl font-bold mb-4">
            Our <span className="gradient-text">Process</span>
          </h2>
          <p className="text-xl text-gray-400">Simple, efficient, and transparent</p>
        </motion.div>

        <div className="grid md:grid-cols-4 gap-8">
          {[
            { step: '01', title: 'Consult', desc: 'Discuss your vision and requirements' },
            { step: '02', title: 'Design', desc: 'Create unique concepts for your brand' },
            { step: '03', title: 'Refine', desc: 'Perfect the design based on your feedback' },
            { step: '04', title: 'Deliver', desc: 'Receive your files in all formats' },
          ].map((item, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              viewport={{ once: true }}
              className="text-center"
            >
              <motion.div
                whileHover={{ scale: 1.1, rotate: 5 }}
                className="w-24 h-24 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-nawi-blue/20 to-nawi-purple/20 
                         flex items-center justify-center border border-white/10"
              >
                <span className="text-3xl font-bold gradient-text">{item.step}</span>
              </motion.div>
              <h3 className="text-xl font-semibold mb-2">{item.title}</h3>
              <p className="text-gray-400">{item.desc}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* CTA Section */}
      <section className="container mx-auto px-4 mt-20">
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          whileInView={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.8 }}
          viewport={{ once: true }}
          className="glass-effect rounded-3xl p-12 text-center relative overflow-hidden"
        >
          <div className="relative z-10">
            <SparklesIcon className="w-16 h-16 mx-auto mb-6 text-yellow-400" />
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Ready to Start Your Project?
            </h2>
            <p className="text-xl text-gray-300 mb-8 max-w-2xl mx-auto">
              Let's create something amazing together. Contact us today for a free consultation.
            </p>
            <Link
              to="/contact"
              className="button-primary inline-flex items-center gap-2 text-lg"
            >
              Get Started
              <ArrowRightIcon className="w-6 h-6" />
            </Link>
          </div>

          {/* Background Animation */}
          <motion.div
            animate={{
              scale: [1, 1.5, 1],
              rotate: [0, 180, 360],
            }}
            transition={{
              duration: 20,
              repeat: Infinity,
              ease: 'linear',
            }}
            className="absolute -top-20 -right-20 w-60 h-60 bg-gradient-to-br from-nawi-blue/30 to-nawi-purple/30 rounded-full blur-3xl"
          />
        </motion.div>
      </section>
    </div>
  )
}

export default Services