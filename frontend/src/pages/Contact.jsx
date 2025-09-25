import { useState } from 'react'
import { motion } from 'framer-motion'
import { useForm } from 'react-hook-form'
import axios from 'axios'
import toast from 'react-hot-toast'
import {
  EnvelopeIcon,
  PhoneIcon,
  MapPinIcon,
  ClockIcon,
  ChatBubbleLeftRightIcon,
  PaperAirplaneIcon,
} from '@heroicons/react/24/outline'

const Contact = () => {
  const [loading, setLoading] = useState(false)
  const { register, handleSubmit, reset, formState: { errors } } = useForm()

  const contactInfo = [
    {
      icon: <EnvelopeIcon className="w-6 h-6" />,
      title: 'Email',
      value: 'nawycompany@gmail.com',
      link: 'mailto:nawycompany@gmail.com',
      color: 'from-blue-500 to-cyan-500',
    },
    {
      icon: <PhoneIcon className="w-6 h-6" />,
      title: 'Phone',
      value: '+20 120 631 5886',
      link: 'tel:+201206315886',
      color: 'from-purple-500 to-pink-500',
    },
    {
      icon: <ChatBubbleLeftRightIcon className="w-6 h-6" />,
      title: 'WhatsApp',
      value: 'Chat with us',
      link: 'https://wa.me/201206315886',
      color: 'from-green-500 to-emerald-500',
    },
    {
      icon: <MapPinIcon className="w-6 h-6" />,
      title: 'Location',
      value: 'Cairo, Egypt',
      link: '#',
      color: 'from-orange-500 to-red-500',
    },
  ]

  const onSubmit = async (data) => {
    setLoading(true)
    try {
      await axios.post('/api/contact', data)
      toast.success('Message sent successfully! We\'ll get back to you soon.')
      reset()
    } catch (error) {
      toast.error('Failed to send message. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const formFields = [
    { name: 'name', label: 'Your Name', type: 'text', required: true },
    { name: 'email', label: 'Email Address', type: 'email', required: true },
    { name: 'phone', label: 'Phone Number', type: 'tel', required: false },
    { name: 'subject', label: 'Subject', type: 'text', required: false },
  ]

  return (
    <div className="min-h-screen pt-32 pb-20">
      {/* Hero Section */}
      <section className="container mx-auto px-4 mb-16">
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="text-center"
        >
          <h1 className="text-5xl md:text-6xl font-bold mb-6">
            Get In <span className="gradient-text">Touch</span>
          </h1>
          <p className="text-xl text-gray-400 max-w-3xl mx-auto">
            Let's discuss your project and bring your creative vision to life
          </p>
        </motion.div>
      </section>

      <div className="container mx-auto px-4">
        <div className="grid lg:grid-cols-2 gap-12">
          {/* Contact Form */}
          <motion.div
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8 }}
          >
            <div className="glass-effect rounded-3xl p-8">
              <h2 className="text-3xl font-bold mb-2">Send Us a Message</h2>
              <p className="text-gray-400 mb-8">
                Fill out the form below and we'll get back to you within 24 hours
              </p>

              <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
                <div className="grid md:grid-cols-2 gap-6">
                  {formFields.slice(0, 2).map((field) => (
                    <motion.div
                      key={field.name}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3 }}
                    >
                      <label className="block text-sm font-medium mb-2">
                        {field.label} {field.required && <span className="text-red-500">*</span>}
                      </label>
                      <input
                        type={field.type}
                        {...register(field.name, {
                          required: field.required ? `${field.label} is required` : false,
                          pattern: field.type === 'email' ? {
                            value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
                            message: 'Invalid email address'
                          } : undefined
                        })}
                        className="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 
                                 focus:border-nawi-blue focus:outline-none focus:ring-2 focus:ring-nawi-blue/50
                                 transition-all duration-300"
                        placeholder={`Enter your ${field.label.toLowerCase()}`}
                      />
                      {errors[field.name] && (
                        <motion.p
                          initial={{ opacity: 0, y: -10 }}
                          animate={{ opacity: 1, y: 0 }}
                          className="mt-1 text-sm text-red-500"
                        >
                          {errors[field.name].message}
                        </motion.p>
                      )}
                    </motion.div>
                  ))}
                </div>

                <div className="grid md:grid-cols-2 gap-6">
                  {formFields.slice(2, 4).map((field) => (
                    <motion.div
                      key={field.name}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.3, delay: 0.1 }}
                    >
                      <label className="block text-sm font-medium mb-2">
                        {field.label} {field.required && <span className="text-red-500">*</span>}
                      </label>
                      <input
                        type={field.type}
                        {...register(field.name, {
                          required: field.required ? `${field.label} is required` : false
                        })}
                        className="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 
                                 focus:border-nawi-blue focus:outline-none focus:ring-2 focus:ring-nawi-blue/50
                                 transition-all duration-300"
                        placeholder={`Enter ${field.label.toLowerCase()}`}
                      />
                    </motion.div>
                  ))}
                </div>

                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: 0.2 }}
                >
                  <label className="block text-sm font-medium mb-2">
                    Message <span className="text-red-500">*</span>
                  </label>
                  <textarea
                    {...register('message', { required: 'Message is required' })}
                    rows={6}
                    className="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 
                             focus:border-nawi-blue focus:outline-none focus:ring-2 focus:ring-nawi-blue/50
                             transition-all duration-300 resize-none"
                    placeholder="Tell us about your project..."
                  />
                  {errors.message && (
                    <motion.p
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="mt-1 text-sm text-red-500"
                    >
                      {errors.message.message}
                    </motion.p>
                  )}
                </motion.div>

                <motion.button
                  type="submit"
                  disabled={loading}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="w-full button-primary flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      Sending...
                    </>
                  ) : (
                    <>
                      <PaperAirplaneIcon className="w-5 h-5" />
                      Send Message
                    </>
                  )}
                </motion.button>
              </form>
            </div>
          </motion.div>

          {/* Contact Info & Map */}
          <motion.div
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8 }}
            className="space-y-8"
          >
            {/* Contact Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {contactInfo.map((info, index) => (
                <motion.a
                  key={index}
                  href={info.link}
                  target={info.link.startsWith('http') ? '_blank' : undefined}
                  rel={info.link.startsWith('http') ? 'noopener noreferrer' : undefined}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: index * 0.1 }}
                  whileHover={{ y: -5, scale: 1.02 }}
                  className="glass-effect rounded-2xl p-6 group cursor-pointer"
                >
                  <div className="flex items-start space-x-4">
                    <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${info.color} 
                                  flex items-center justify-center group-hover:scale-110 transition-transform`}>
                      {info.icon}
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold mb-1">{info.title}</h3>
                      <p className="text-gray-400 text-sm">{info.value}</p>
                    </div>
                  </div>
                </motion.a>
              ))}
            </div>

            {/* Working Hours */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.4 }}
              className="glass-effect rounded-3xl p-8"
            >
              <div className="flex items-center space-x-3 mb-6">
                <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-yellow-500 to-orange-500 
                              flex items-center justify-center">
                  <ClockIcon className="w-6 h-6" />
                </div>
                <h3 className="text-2xl font-bold">Working Hours</h3>
              </div>
              
              <div className="space-y-4">
                <div className="flex justify-between items-center py-3 border-b border-white/10">
                  <span className="text-gray-400">Monday - Friday</span>
                  <span className="font-medium">9:00 AM - 7:00 PM</span>
                </div>
                <div className="flex justify-between items-center py-3 border-b border-white/10">
                  <span className="text-gray-400">Saturday</span>
                  <span className="font-medium">10:00 AM - 5:00 PM</span>
                </div>
                <div className="flex justify-between items-center py-3">
                  <span className="text-gray-400">Sunday</span>
                  <span className="font-medium text-red-400">Closed</span>
                </div>
              </div>
            </motion.div>

            {/* Map Placeholder */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.5 }}
              className="glass-effect rounded-3xl p-8 h-64 relative overflow-hidden group"
            >
              <div className="absolute inset-0 bg-gradient-to-br from-nawi-blue/20 to-nawi-purple/20" />
              <div className="relative z-10 h-full flex flex-col items-center justify-center text-center">
                <MapPinIcon className="w-12 h-12 mb-4 text-nawi-blue" />
                <h3 className="text-xl font-bold mb-2">Visit Our Office</h3>
                <p className="text-gray-400">Cairo, Egypt</p>
                <button className="mt-4 px-6 py-2 rounded-full bg-white/10 hover:bg-white/20 
                                 transition-colors border border-white/20">
                  Get Directions
                </button>
              </div>
              
              {/* Animated Background */}
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
                className="absolute -bottom-20 -right-20 w-40 h-40 bg-gradient-to-br from-nawi-blue/30 to-nawi-purple/30 rounded-full blur-3xl"
              />
            </motion.div>
          </motion.div>
        </div>
      </div>

      {/* FAQ Section */}
      <section className="container mx-auto px-4 mt-20">
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <h2 className="text-4xl font-bold mb-4">
            Frequently Asked <span className="gradient-text">Questions</span>
          </h2>
          <p className="text-xl text-gray-400">Quick answers to common queries</p>
        </motion.div>

        <div className="max-w-3xl mx-auto space-y-4">
          {[
            {
              question: 'How long does a typical project take?',
              answer: 'Project timelines vary based on complexity. Logo design typically takes 3-5 days, while full brand identity projects can take 2-3 weeks.',
            },
            {
              question: 'What file formats will I receive?',
              answer: 'You\'ll receive all necessary formats including AI, EPS, SVG, PNG, and JPG files, along with a brand guidelines document.',
            },
            {
              question: 'Do you offer revisions?',
              answer: 'Yes! We offer unlimited revisions until you\'re completely satisfied with the design.',
            },
            {
              question: 'What payment methods do you accept?',
              answer: 'We accept bank transfers, PayPal, and various digital payment methods. Payment terms are 50% upfront and 50% upon completion.',
            },
          ].map((faq, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              viewport={{ once: true }}
              className="glass-effect rounded-2xl p-6"
            >
              <h3 className="text-lg font-semibold mb-2">{faq.question}</h3>
              <p className="text-gray-400">{faq.answer}</p>
            </motion.div>
          ))}
        </div>
      </section>
    </div>
  )
}

export default Contact