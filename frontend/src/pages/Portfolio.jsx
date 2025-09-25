import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import axios from 'axios'
import toast from 'react-hot-toast'
import {
  MagnifyingGlassIcon,
  XMarkIcon,
  HeartIcon,
  ShareIcon,
  ArrowsPointingOutIcon,
} from '@heroicons/react/24/outline'
import { HeartIcon as HeartIconSolid } from '@heroicons/react/24/solid'

const Portfolio = () => {
  const [portfolio, setPortfolio] = useState([])
  const [filteredPortfolio, setFilteredPortfolio] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [selectedItem, setSelectedItem] = useState(null)
  const [likedItems, setLikedItems] = useState(new Set())

  const categories = [
    { id: 'all', name: 'All Works', icon: '🎨' },
    { id: 'branding', name: 'Branding', icon: '🏷️' },
    { id: 'social', name: 'Social Media', icon: '📱' },
    { id: 'print', name: 'Print Design', icon: '🖨️' },
    { id: 'web', name: 'Web Design', icon: '🌐' },
  ]

  useEffect(() => {
    fetchPortfolio()
    // Load liked items from localStorage
    const saved = localStorage.getItem('likedPortfolio')
    if (saved) {
      setLikedItems(new Set(JSON.parse(saved)))
    }
  }, [])

  useEffect(() => {
    filterPortfolio()
  }, [selectedCategory, portfolio])

  const fetchPortfolio = async () => {
    try {
      const response = await axios.get('/api/portfolio')
      setPortfolio(response.data)
      setFilteredPortfolio(response.data)
    } catch (error) {
      toast.error('Failed to load portfolio')
    } finally {
      setLoading(false)
    }
  }

  const filterPortfolio = () => {
    if (selectedCategory === 'all') {
      setFilteredPortfolio(portfolio)
    } else {
      setFilteredPortfolio(portfolio.filter(item => item.category === selectedCategory))
    }
  }

  const toggleLike = (itemId) => {
    const newLiked = new Set(likedItems)
    if (newLiked.has(itemId)) {
      newLiked.delete(itemId)
      toast.success('Removed from favorites')
    } else {
      newLiked.add(itemId)
      toast.success('Added to favorites!')
    }
    setLikedItems(newLiked)
    localStorage.setItem('likedPortfolio', JSON.stringify(Array.from(newLiked)))
  }

  const shareItem = (item) => {
    if (navigator.share) {
      navigator.share({
        title: item.title,
        text: item.description,
        url: window.location.href,
      })
    } else {
      navigator.clipboard.writeText(window.location.href)
      toast.success('Link copied to clipboard!')
    }
  }

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
            Our <span className="gradient-text">Portfolio</span>
          </h1>
          <p className="text-xl text-gray-400 max-w-3xl mx-auto">
            Explore our creative journey through stunning designs that tell unique stories
          </p>
        </motion.div>
      </section>

      {/* Category Filter */}
      <section className="container mx-auto px-4 mb-12">
        <div className="flex flex-wrap justify-center gap-4">
          {categories.map((category, index) => (
            <motion.button
              key={category.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: index * 0.1 }}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => setSelectedCategory(category.id)}
              className={`px-6 py-3 rounded-full font-medium transition-all ${
                selectedCategory === category.id
                  ? 'bg-gradient-to-r from-nawi-blue to-nawi-purple text-white shadow-lg'
                  : 'glass-effect hover:bg-white/10'
              }`}
            >
              <span className="mr-2">{category.icon}</span>
              {category.name}
            </motion.button>
          ))}
        </div>
      </section>

      {/* Portfolio Grid */}
      <section className="container mx-auto px-4">
        {loading ? (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {[1, 2, 3, 4, 5, 6].map((i) => (
              <div key={i} className="aspect-square glass-effect rounded-2xl animate-pulse" />
            ))}
          </div>
        ) : filteredPortfolio.length === 0 ? (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-center py-20"
          >
            <p className="text-2xl text-gray-400">No projects found in this category</p>
          </motion.div>
        ) : (
          <motion.div
            layout
            className="grid md:grid-cols-2 lg:grid-cols-3 gap-8"
          >
            <AnimatePresence>
              {filteredPortfolio.map((item, index) => (
                <motion.div
                  key={item.id}
                  layout
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.8 }}
                  transition={{ duration: 0.3, delay: index * 0.05 }}
                  whileHover={{ y: -10 }}
                  className="group relative cursor-pointer"
                  onClick={() => setSelectedItem(item)}
                >
                  <div className="relative overflow-hidden rounded-2xl glass-effect">
                    {/* Image */}
                    <div className="aspect-square bg-gradient-to-br from-nawi-blue/20 to-nawi-purple/20">
                      {item.image_url && (
                        <img
                          src={item.thumbnail_url || item.image_url}
                          alt={item.title}
                          className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-500"
                        />
                      )}
                    </div>

                    {/* Overlay */}
                    <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-black/40 to-transparent 
                                  opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                      <div className="absolute bottom-0 left-0 right-0 p-6">
                        <h3 className="text-xl font-bold mb-2">{item.title}</h3>
                        <p className="text-gray-300 text-sm mb-3 line-clamp-2">{item.description}</p>
                        
                        <div className="flex items-center justify-between">
                          <div className="flex gap-2">
                            {item.tags.map((tag, i) => (
                              <span
                                key={i}
                                className="px-2 py-1 text-xs rounded-full bg-white/20 backdrop-blur"
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                          
                          <motion.button
                            whileHover={{ scale: 1.2 }}
                            whileTap={{ scale: 0.9 }}
                            onClick={(e) => {
                              e.stopPropagation()
                              toggleLike(item.id)
                            }}
                            className="p-2 rounded-full bg-white/20 backdrop-blur"
                          >
                            {likedItems.has(item.id) ? (
                              <HeartIconSolid className="w-5 h-5 text-red-500" />
                            ) : (
                              <HeartIcon className="w-5 h-5" />
                            )}
                          </motion.button>
                        </div>
                      </div>
                    </div>

                    {/* Featured Badge */}
                    {item.is_featured && (
                      <motion.div
                        initial={{ rotate: -45, x: -50 }}
                        animate={{ rotate: -45, x: 0 }}
                        className="absolute top-4 -left-12 bg-gradient-to-r from-yellow-400 to-orange-400 
                                 text-black text-xs font-bold py-1 px-12 transform"
                      >
                        Featured
                      </motion.div>
                    )}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </motion.div>
        )}
      </section>

      {/* Portfolio Modal */}
      <AnimatePresence>
        {selectedItem && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/90 backdrop-blur-xl z-50 flex items-center justify-center p-4"
            onClick={() => setSelectedItem(null)}
          >
            <motion.div
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.8, opacity: 0 }}
              transition={{ type: 'spring', damping: 25 }}
              className="relative max-w-6xl w-full max-h-[90vh] overflow-hidden rounded-3xl glass-effect"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header */}
              <div className="absolute top-0 left-0 right-0 p-6 bg-gradient-to-b from-black/80 to-transparent z-10">
                <div className="flex justify-between items-start">
                  <div>
                    <h2 className="text-3xl font-bold mb-2">{selectedItem.title}</h2>
                    {selectedItem.client_name && (
                      <p className="text-gray-400">Client: {selectedItem.client_name}</p>
                    )}
                  </div>
                  
                  <div className="flex gap-2">
                    <motion.button
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                      onClick={() => toggleLike(selectedItem.id)}
                      className="p-3 rounded-full glass-effect hover:bg-white/20"
                    >
                      {likedItems.has(selectedItem.id) ? (
                        <HeartIconSolid className="w-6 h-6 text-red-500" />
                      ) : (
                        <HeartIcon className="w-6 h-6" />
                      )}
                    </motion.button>
                    
                    <motion.button
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                      onClick={() => shareItem(selectedItem)}
                      className="p-3 rounded-full glass-effect hover:bg-white/20"
                    >
                      <ShareIcon className="w-6 h-6" />
                    </motion.button>
                    
                    <motion.button
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                      onClick={() => setSelectedItem(null)}
                      className="p-3 rounded-full glass-effect hover:bg-white/20"
                    >
                      <XMarkIcon className="w-6 h-6" />
                    </motion.button>
                  </div>
                </div>
              </div>

              {/* Image */}
              <div className="relative">
                <img
                  src={selectedItem.image_url}
                  alt={selectedItem.title}
                  className="w-full h-auto max-h-[80vh] object-contain"
                />
                
                {/* Description Overlay */}
                <div className="absolute bottom-0 left-0 right-0 p-6 bg-gradient-to-t from-black/90 to-transparent">
                  <p className="text-gray-300 mb-4">{selectedItem.description}</p>
                  
                  {selectedItem.tags.length > 0 && (
                    <div className="flex flex-wrap gap-2">
                      {selectedItem.tags.map((tag, i) => (
                        <span
                          key={i}
                          className="px-3 py-1 text-sm rounded-full bg-gradient-to-r from-nawi-blue/20 to-nawi-purple/20 
                                   border border-white/20 backdrop-blur"
                        >
                          #{tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Stats Section */}
      <section className="container mx-auto px-4 mt-20">
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          viewport={{ once: true }}
          className="glass-effect rounded-3xl p-12"
        >
          <div className="grid md:grid-cols-4 gap-8 text-center">
            <div>
              <motion.div
                initial={{ scale: 0 }}
                whileInView={{ scale: 1 }}
                transition={{ duration: 0.5, type: 'spring' }}
                viewport={{ once: true }}
                className="text-4xl font-bold gradient-text mb-2"
              >
                500+
              </motion.div>
              <p className="text-gray-400">Projects Completed</p>
            </div>
            <div>
              <motion.div
                initial={{ scale: 0 }}
                whileInView={{ scale: 1 }}
                transition={{ duration: 0.5, delay: 0.1, type: 'spring' }}
                viewport={{ once: true }}
                className="text-4xl font-bold gradient-text mb-2"
              >
                250+
              </motion.div>
              <p className="text-gray-400">Happy Clients</p>
            </div>
            <div>
              <motion.div
                initial={{ scale: 0 }}
                whileInView={{ scale: 1 }}
                transition={{ duration: 0.5, delay: 0.2, type: 'spring' }}
                viewport={{ once: true }}
                className="text-4xl font-bold gradient-text mb-2"
              >
                50+
              </motion.div>
              <p className="text-gray-400">Design Awards</p>
            </div>
            <div>
              <motion.div
                initial={{ scale: 0 }}
                whileInView={{ scale: 1 }}
                transition={{ duration: 0.5, delay: 0.3, type: 'spring' }}
                viewport={{ once: true }}
                className="text-4xl font-bold gradient-text mb-2"
              >
                99%
              </motion.div>
              <p className="text-gray-400">Client Satisfaction</p>
            </div>
          </div>
        </motion.div>
      </section>
    </div>
  )
}

export default Portfolio