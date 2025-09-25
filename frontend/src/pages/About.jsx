import { motion } from 'framer-motion'
import { useInView } from 'react-intersection-observer'
import {
  SparklesIcon,
  LightBulbIcon,
  HeartIcon,
  RocketLaunchIcon,
  UserGroupIcon,
  TrophyIcon,
} from '@heroicons/react/24/outline'
import CountUp from 'react-countup'

const About = () => {
  const [titleRef, titleInView] = useInView({ threshold: 0.1, triggerOnce: true })
  const [storyRef, storyInView] = useInView({ threshold: 0.1, triggerOnce: true })
  const [valuesRef, valuesInView] = useInView({ threshold: 0.1, triggerOnce: true })
  const [teamRef, teamInView] = useInView({ threshold: 0.1, triggerOnce: true })

  const values = [
    {
      icon: <SparklesIcon className="w-8 h-8" />,
      title: 'Creativity',
      description: 'We push boundaries and think outside the box to deliver unique designs',
      color: 'from-blue-500 to-cyan-500',
    },
    {
      icon: <HeartIcon className="w-8 h-8" />,
      title: 'Passion',
      description: 'We love what we do and it shows in every pixel we craft',
      color: 'from-purple-500 to-pink-500',
    },
    {
      icon: <LightBulbIcon className="w-8 h-8" />,
      title: 'Innovation',
      description: 'We stay ahead of trends and embrace new technologies',
      color: 'from-yellow-500 to-orange-500',
    },
    {
      icon: <RocketLaunchIcon className="w-8 h-8" />,
      title: 'Excellence',
      description: 'We deliver nothing but the best quality in every project',
      color: 'from-green-500 to-teal-500',
    },
  ]

  const timeline = [
    { year: '2019', event: 'Nawi was founded with a vision to transform brands', icon: '🚀' },
    { year: '2020', event: 'Expanded our services to include digital marketing', icon: '📈' },
    { year: '2021', event: 'Reached 100+ satisfied clients milestone', icon: '🎉' },
    { year: '2022', event: 'Launched our innovative design system', icon: '💡' },
    { year: '2023', event: 'Won multiple design awards and recognition', icon: '🏆' },
    { year: '2024', event: 'Continuing to innovate and inspire', icon: '✨' },
  ]

  const team = [
    {
      name: 'Ahmed Hassan',
      role: 'Creative Director',
      image: '/team1.jpg',
      social: { twitter: '#', linkedin: '#', behance: '#' },
    },
    {
      name: 'Sara Mohamed',
      role: 'Lead Designer',
      image: '/team2.jpg',
      social: { twitter: '#', linkedin: '#', behance: '#' },
    },
    {
      name: 'Omar Ali',
      role: 'UI/UX Designer',
      image: '/team3.jpg',
      social: { twitter: '#', linkedin: '#', behance: '#' },
    },
    {
      name: 'Fatima Ahmed',
      role: 'Brand Strategist',
      image: '/team4.jpg',
      social: { twitter: '#', linkedin: '#', behance: '#' },
    },
  ]

  return (
    <div className="min-h-screen pt-32 pb-20">
      {/* Hero Section */}
      <section ref={titleRef} className="container mx-auto px-4 mb-20">
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={titleInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.8 }}
          className="text-center"
        >
          <div className="mb-6">
            <h1 className="text-5xl md:text-6xl font-bold mb-4">About</h1>
            <img src="/nawi-text-logo.png" alt="Nawi" className="h-24 md:h-32 lg:h-40 object-contain mx-auto" />
          </div>
          <p className="text-xl text-gray-400 max-w-3xl mx-auto mb-8">
            We're a creative design studio that transforms ideas into powerful visual identities
          </p>
          
          {/* Arabic Tagline */}
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={titleInView ? { opacity: 1, scale: 1 } : {}}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="inline-block"
          >
            <div className="glass-effect rounded-2xl px-8 py-6">
              <img src="/nawi-text-logo.png" alt="ناوي" className="h-16 md:h-20 object-contain mx-auto mb-4" />
              <p className="text-lg text-gray-300">فريق التصميم اللي بيحوّل فكرتك لهوية</p>
            </div>
          </motion.div>
        </motion.div>
      </section>

      {/* Our Story Section */}
      <section ref={storyRef} className="container mx-auto px-4 mb-20">
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <motion.div
            initial={{ opacity: 0, x: -50 }}
            animate={storyInView ? { opacity: 1, x: 0 } : {}}
            transition={{ duration: 0.8 }}
          >
            <h2 className="text-4xl font-bold mb-6">
              Our <span className="gradient-text">Story</span>
            </h2>
            <div className="space-y-4 text-gray-300">
              <p>
                Founded in 2019, Nawi emerged from a passion for creative excellence and a vision 
                to help brands tell their unique stories through compelling design.
              </p>
              <p>
                What started as a small team of creative enthusiasts has grown into a full-service 
                design studio, serving clients across the Middle East and beyond. We believe that 
                great design has the power to transform businesses and connect with audiences on 
                a deeper level.
              </p>
              <p>
                Our name "Nawi" (ناوي) means "intending" or "determined" in Arabic, reflecting our 
                commitment to purposeful design and our determination to exceed client expectations 
                in every project we undertake.
              </p>
            </div>
            
            {/* Stats */}
            <div className="grid grid-cols-2 gap-6 mt-8">
              {[
                { value: 5, label: 'Years of Excellence', suffix: '+' },
                { value: 250, label: 'Happy Clients', suffix: '+' },
              ].map((stat, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 20 }}
                  animate={storyInView ? { opacity: 1, y: 0 } : {}}
                  transition={{ duration: 0.5, delay: 0.2 + index * 0.1 }}
                  className="glass-effect rounded-xl p-4"
                >
                  <div className="text-3xl font-bold gradient-text">
                    {storyInView && (
                      <CountUp end={stat.value} duration={2} suffix={stat.suffix} />
                    )}
                  </div>
                  <p className="text-sm text-gray-400">{stat.label}</p>
                </motion.div>
              ))}
            </div>
          </motion.div>

          {/* Timeline */}
          <motion.div
            initial={{ opacity: 0, x: 50 }}
            animate={storyInView ? { opacity: 1, x: 0 } : {}}
            transition={{ duration: 0.8 }}
            className="relative"
          >
            <div className="absolute left-8 top-0 bottom-0 w-0.5 bg-gradient-to-b from-nawi-blue to-nawi-purple" />
            
            {timeline.map((item, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, x: 50 }}
                animate={storyInView ? { opacity: 1, x: 0 } : {}}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className="relative flex items-center mb-8"
              >
                <motion.div
                  whileHover={{ scale: 1.2, rotate: 360 }}
                  transition={{ duration: 0.5 }}
                  className="w-16 h-16 rounded-full bg-gradient-to-br from-nawi-blue to-nawi-purple 
                           flex items-center justify-center z-10 shadow-lg glow-effect"
                >
                  <span className="text-2xl">{item.icon}</span>
                </motion.div>
                
                <motion.div
                  whileHover={{ x: 5 }}
                  className="ml-8 glass-effect rounded-xl p-4 flex-1"
                >
                  <p className="text-sm text-nawi-blue font-semibold">{item.year}</p>
                  <p className="text-gray-300">{item.event}</p>
                </motion.div>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Values Section */}
      <section ref={valuesRef} className="container mx-auto px-4 mb-20">
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={valuesInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.8 }}
          className="text-center mb-12"
        >
          <h2 className="text-4xl font-bold mb-4">
            Our <span className="gradient-text">Values</span>
          </h2>
          <p className="text-xl text-gray-400">The principles that guide everything we do</p>
        </motion.div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
          {values.map((value, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 50 }}
              animate={valuesInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              whileHover={{ y: -10, scale: 1.05 }}
              className="relative group"
            >
              <div className="glass-effect rounded-2xl p-6 h-full">
                <motion.div
                  whileHover={{ rotate: 360, scale: 1.1 }}
                  transition={{ duration: 0.5 }}
                  className={`w-16 h-16 rounded-xl bg-gradient-to-br ${value.color} 
                           flex items-center justify-center mb-4 group-hover:shadow-2xl transition-all`}
                >
                  {value.icon}
                </motion.div>
                
                <h3 className="text-xl font-semibold mb-2">{value.title}</h3>
                <p className="text-gray-400">{value.description}</p>
                
                {/* Hover Effect */}
                <div className={`absolute inset-0 bg-gradient-to-br ${value.color} 
                             opacity-0 group-hover:opacity-10 rounded-2xl transition-opacity duration-300`} />
              </div>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Team Section */}
      <section ref={teamRef} className="container mx-auto px-4 mb-20">
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={teamInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.8 }}
          className="text-center mb-12"
        >
          <h2 className="text-4xl font-bold mb-4">
            Meet Our <span className="gradient-text">Team</span>
          </h2>
          <p className="text-xl text-gray-400">The creative minds behind Nawi</p>
        </motion.div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
          {team.map((member, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={teamInView ? { opacity: 1, scale: 1 } : {}}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              whileHover={{ y: -10 }}
              className="group"
            >
              <div className="glass-effect rounded-2xl p-6 text-center">
                <motion.div
                  whileHover={{ scale: 1.05 }}
                  className="w-32 h-32 mx-auto mb-4 rounded-full bg-gradient-to-br from-nawi-blue to-nawi-purple p-1"
                >
                  <div className="w-full h-full rounded-full bg-nawi-dark flex items-center justify-center">
                    <UserGroupIcon className="w-16 h-16 text-gray-400" />
                  </div>
                </motion.div>
                
                <h3 className="text-xl font-semibold mb-1">{member.name}</h3>
                <p className="text-nawi-blue mb-4">{member.role}</p>
                
                {/* Social Links */}
                <div className="flex justify-center space-x-3">
                  {Object.entries(member.social).map(([platform, link]) => (
                    <motion.a
                      key={platform}
                      href={link}
                      whileHover={{ scale: 1.2, rotate: 5 }}
                      whileTap={{ scale: 0.9 }}
                      className="w-8 h-8 rounded-full bg-white/10 hover:bg-white/20 
                               flex items-center justify-center transition-colors"
                    >
                      <span className="text-xs">
                        {platform === 'twitter' && '𝕏'}
                        {platform === 'linkedin' && 'in'}
                        {platform === 'behance' && 'Be'}
                      </span>
                    </motion.a>
                  ))}
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </section>

      {/* CTA Section */}
      <section className="container mx-auto px-4">
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          whileInView={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.8 }}
          viewport={{ once: true }}
          className="relative overflow-hidden rounded-3xl"
        >
          <div className="absolute inset-0 animated-gradient-bg opacity-80" />
          
          <div className="relative z-10 glass-effect rounded-3xl p-12 text-center">
            <TrophyIcon className="w-16 h-16 mx-auto mb-6 text-yellow-400" />
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Let's Create Something Amazing Together
            </h2>
            <p className="text-xl text-gray-200 mb-8 max-w-2xl mx-auto">
              Join the growing list of brands that trust Nawi with their visual identity
            </p>
            <motion.a
              href="/contact"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="button-primary inline-flex items-center gap-2 text-lg"
            >
              Start Your Journey
              <SparklesIcon className="w-6 h-6" />
            </motion.a>
          </div>
        </motion.div>
      </section>
    </div>
  )
}

export default About