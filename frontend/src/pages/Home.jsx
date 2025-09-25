import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { useInView } from 'react-intersection-observer'
import { 
  SparklesIcon, 
  PaintBrushIcon, 
  DevicePhoneMobileIcon,
  GlobeAltIcon,
  ChartBarIcon,
  RocketLaunchIcon,
  StarIcon,
  ArrowRightIcon
} from '@heroicons/react/24/outline'
import CountUp from 'react-countup'

const Home = () => {
  const [heroRef, heroInView] = useInView({ threshold: 0.1, triggerOnce: true })
  const [statsRef, statsInView] = useInView({ threshold: 0.1, triggerOnce: true })
  const [featuresRef, featuresInView] = useInView({ threshold: 0.1, triggerOnce: true })

  const stats = [
    { value: 250, label: 'Happy Clients', suffix: '+' },
    { value: 500, label: 'Projects Completed', suffix: '+' },
    { value: 99, label: 'Client Satisfaction', suffix: '%' },
    { value: 5, label: 'Years Experience', suffix: '+' },
  ]

  const features = [
    {
      icon: <PaintBrushIcon className="w-8 h-8" />,
      title: 'Creative Design',
      description: 'Unique and innovative designs that capture your brand essence',
      color: 'from-blue-500 to-cyan-500',
    },
    {
      icon: <DevicePhoneMobileIcon className="w-8 h-8" />,
      title: 'Social Media Ready',
      description: 'Optimized designs for all social media platforms',
      color: 'from-purple-500 to-pink-500',
    },
    {
      icon: <GlobeAltIcon className="w-8 h-8" />,
      title: 'Global Reach',
      description: 'Designs that resonate with international audiences',
      color: 'from-green-500 to-teal-500',
    },
    {
      icon: <RocketLaunchIcon className="w-8 h-8" />,
      title: 'Fast Delivery',
      description: 'Quick turnaround times without compromising quality',
      color: 'from-orange-500 to-red-500',
    },
  ]

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section
        ref={heroRef}
        className="min-h-screen flex items-center justify-center relative overflow-hidden pt-20"
      >
        {/* Animated Background Gradient */}
        <div className="absolute inset-0 animated-gradient-bg opacity-20" />
        
        {/* Floating Elements */}
        <motion.div
          animate={{
            y: [0, -20, 0],
            rotate: [0, 5, -5, 0],
          }}
          transition={{
            duration: 6,
            repeat: Infinity,
            repeatType: 'loop',
          }}
          className="absolute top-20 left-10 w-20 h-20 bg-gradient-to-br from-nawi-blue to-nawi-purple rounded-full opacity-30 blur-xl"
        />
        <motion.div
          animate={{
            y: [0, 20, 0],
            rotate: [0, -5, 5, 0],
          }}
          transition={{
            duration: 8,
            repeat: Infinity,
            repeatType: 'loop',
          }}
          className="absolute bottom-20 right-10 w-32 h-32 bg-gradient-to-br from-nawi-purple to-pink-500 rounded-full opacity-30 blur-2xl"
        />

        <div className="container mx-auto px-4 relative z-10">
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            animate={heroInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.8 }}
            className="text-center"
          >
            {/* Logo */}
            <motion.div
              initial={{ scale: 0 }}
              animate={heroInView ? { scale: 1 } : {}}
              transition={{ duration: 0.5, type: 'spring' }}
              className="inline-block mb-8"
            >
              <div className="relative">
                <div className="w-40 h-40 mx-auto rounded-3xl flex items-center justify-center shadow-lg overflow-hidden relative z-10">
                  <img src="/nawi-logo.png" alt="Nawi Logo" className="w-36 h-36 object-contain" />
                </div>
                <motion.div
                  animate={{
                    scale: [1, 1.1, 1],
                    opacity: [0.15, 0.3, 0.15],
                  }}
                  transition={{
                    duration: 3,
                    repeat: Infinity,
                  }}
                  className="absolute inset-0 w-40 h-40 bg-gradient-to-br from-nawi-blue to-nawi-purple rounded-3xl blur-2xl -z-10"
                />
              </div>
            </motion.div>

            {/* Title */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={heroInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.8, delay: 0.2 }}
              className="mb-6 flex justify-center relative"
            >
              <div className="relative">
                {/* Beautiful Highlight Effect */}
                <motion.div
                  animate={{
                    scale: [1, 1.02, 1],
                    opacity: [0.4, 0.7, 0.4],
                  }}
                  transition={{
                    duration: 4,
                    repeat: Infinity,
                  }}
                  className="absolute inset-0 bg-gradient-to-r from-transparent via-nawi-blue/20 to-transparent rounded-2xl blur-xl transform rotate-1"
                />
                <motion.div
                  animate={{
                    scale: [1.01, 1.03, 1.01],
                    opacity: [0.3, 0.6, 0.3],
                  }}
                  transition={{
                    duration: 5,
                    repeat: Infinity,
                    delay: 0.5,
                  }}
                  className="absolute inset-0 bg-gradient-to-r from-nawi-purple/15 via-transparent to-nawi-purple/15 rounded-2xl blur-lg transform -rotate-1"
                />
                <img src="/nawi-text-logo.png" alt="Nawi" className="relative z-10 h-28 md:h-40 lg:h-48 object-contain" />
              </div>
            </motion.div>

            {/* Tagline */}
            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={heroInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.8, delay: 0.3 }}
              className="text-xl md:text-2xl text-gray-300 mb-8 max-w-3xl mx-auto"
            >
              فريق التصميم اللي بيحوّل فكرتك لهوية
              <br />
              <span className="text-lg text-gray-400">
                The design team that transforms your vision into identity
              </span>
            </motion.p>

            {/* CTA Buttons */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={heroInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.8, delay: 0.4 }}
              className="flex flex-col sm:flex-row gap-4 justify-center"
            >
              <Link
                to="/contact"
                className="button-primary inline-flex items-center gap-2 group"
              >
                اطلب تصميم
                <ArrowRightIcon className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
              </Link>
              <Link
                to="/portfolio"
                className="button-secondary inline-flex items-center gap-2"
              >
                <SparklesIcon className="w-5 h-5" />
                شاهد أعمالنا
              </Link>
            </motion.div>

            {/* Scroll Indicator */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={heroInView ? { opacity: 1 } : {}}
              transition={{ duration: 1, delay: 0.8 }}
              className="absolute bottom-10 left-1/2 transform -translate-x-1/2"
            >
              <motion.div
                animate={{ y: [0, 10, 0] }}
                transition={{ duration: 1.5, repeat: Infinity }}
                className="w-6 h-10 border-2 border-white/30 rounded-full flex justify-center"
              >
                <div className="w-1 h-3 bg-white/50 rounded-full mt-2" />
              </motion.div>
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* Stats Section */}
      <section ref={statsRef} className="py-20 relative">
        <div className="container mx-auto px-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, scale: 0.5 }}
                animate={statsInView ? { opacity: 1, scale: 1 } : {}}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className="text-center"
              >
                <div className="glass-effect rounded-2xl p-6 hover-glow">
                  <div className="text-4xl md:text-5xl font-bold gradient-text mb-2">
                    {statsInView && (
                      <CountUp
                        end={stat.value}
                        duration={2}
                        suffix={stat.suffix}
                      />
                    )}
                  </div>
                  <div className="text-gray-400">{stat.label}</div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section ref={featuresRef} className="py-20 relative">
        <div className="container mx-auto px-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={featuresInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.8 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl md:text-5xl font-bold mb-4">
              Why Choose <span className="gradient-text">Nawi</span>?
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto">
              We bring creativity, innovation, and professionalism to every project
            </p>
          </motion.div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 50 }}
                animate={featuresInView ? { opacity: 1, y: 0 } : {}}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                whileHover={{ y: -10, scale: 1.05 }}
                className="relative group"
              >
                <div className="glass-effect rounded-2xl p-6 h-full">
                  <div
                    className={`w-16 h-16 rounded-xl bg-gradient-to-br ${feature.color} 
                    flex items-center justify-center mb-4 group-hover:scale-110 transition-transform`}
                  >
                    {feature.icon}
                  </div>
                  <h3 className="text-xl font-semibold mb-2">{feature.title}</h3>
                  <p className="text-gray-400">{feature.description}</p>
                  
                  {/* Hover Glow Effect */}
                  <div
                    className={`absolute inset-0 bg-gradient-to-br ${feature.color} 
                    opacity-0 group-hover:opacity-10 rounded-2xl transition-opacity duration-300`}
                  />
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 relative">
        <div className="container mx-auto px-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="relative overflow-hidden rounded-3xl"
          >
            <div className="absolute inset-0 animated-gradient-bg opacity-80" />
            <div className="relative z-10 glass-effect rounded-3xl p-12 text-center">
              <StarIcon className="w-16 h-16 mx-auto mb-6 text-yellow-400" />
              <h2 className="text-3xl md:text-4xl font-bold mb-4">
                Ready to Transform Your Brand?
              </h2>
              <p className="text-xl text-gray-200 mb-8 max-w-2xl mx-auto">
                Let's create something amazing together. Your vision, our expertise.
              </p>
              <Link
                to="/contact"
                className="button-primary inline-flex items-center gap-2 text-lg group"
              >
                Start Your Project
                <ArrowRightIcon className="w-6 h-6 group-hover:translate-x-2 transition-transform" />
              </Link>
            </div>
          </motion.div>
        </div>
      </section>
    </div>
  )
}

export default Home