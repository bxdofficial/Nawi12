import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { useAuth } from '../contexts/AuthContext'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import toast from 'react-hot-toast'
import {
  DocumentTextIcon,
  FolderIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ArrowDownTrayIcon,
  EyeIcon,
} from '@heroicons/react/24/outline'

const Dashboard = () => {
  const { user, isAuthenticated } = useAuth()
  const navigate = useNavigate()
  const [requests, setRequests] = useState([])
  const [designs, setDesigns] = useState([])
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('requests')

  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login')
      return
    }
    fetchUserData()
  }, [isAuthenticated, navigate])

  const fetchUserData = async () => {
    try {
      const [requestsRes, designsRes] = await Promise.all([
        axios.get('/api/requests'),
        axios.get('/api/designs/my')
      ])
      setRequests(requestsRes.data || [])
      setDesigns(designsRes.data || [])
    } catch (error) {
      console.error('Error fetching user data:', error)
    } finally {
      setLoading(false)
    }
  }

  const getStatusColor = (status) => {
    const colors = {
      pending: 'text-yellow-500 bg-yellow-500/10',
      in_progress: 'text-blue-500 bg-blue-500/10',
      completed: 'text-green-500 bg-green-500/10',
      cancelled: 'text-red-500 bg-red-500/10',
    }
    return colors[status] || 'text-gray-500 bg-gray-500/10'
  }

  const getStatusIcon = (status) => {
    const icons = {
      pending: <ClockIcon className="w-5 h-5" />,
      in_progress: <DocumentTextIcon className="w-5 h-5" />,
      completed: <CheckCircleIcon className="w-5 h-5" />,
      cancelled: <XCircleIcon className="w-5 h-5" />,
    }
    return icons[status] || <ClockIcon className="w-5 h-5" />
  }

  if (loading) {
    return (
      <div className="min-h-screen pt-32 flex items-center justify-center">
        <div className="w-16 h-16 border-4 border-nawi-blue border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <div className="min-h-screen pt-32 pb-20">
      <div className="container mx-auto px-4">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-4xl font-bold mb-2">
            Welcome back, <span className="gradient-text">{user?.username}</span>!
          </h1>
          <p className="text-gray-400">Manage your design requests and downloads</p>
        </motion.div>

        {/* Stats Cards */}
        <div className="grid md:grid-cols-4 gap-6 mb-8">
          {[
            { label: 'Total Requests', value: requests.length, icon: <DocumentTextIcon className="w-6 h-6" />, color: 'from-blue-500 to-cyan-500' },
            { label: 'In Progress', value: requests.filter(r => r.status === 'in_progress').length, icon: <ClockIcon className="w-6 h-6" />, color: 'from-purple-500 to-pink-500' },
            { label: 'Completed', value: requests.filter(r => r.status === 'completed').length, icon: <CheckCircleIcon className="w-6 h-6" />, color: 'from-green-500 to-teal-500' },
            { label: 'My Designs', value: designs.length, icon: <FolderIcon className="w-6 h-6" />, color: 'from-orange-500 to-red-500' },
          ].map((stat, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.3, delay: index * 0.1 }}
              whileHover={{ y: -5 }}
              className="glass-effect rounded-2xl p-6"
            >
              <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${stat.color} 
                            flex items-center justify-center mb-4`}>
                {stat.icon}
              </div>
              <p className="text-gray-400 text-sm mb-1">{stat.label}</p>
              <p className="text-3xl font-bold">{stat.value}</p>
            </motion.div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex space-x-4 mb-6">
          {['requests', 'designs'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-6 py-3 rounded-xl font-medium transition-all ${
                activeTab === tab
                  ? 'bg-gradient-to-r from-nawi-blue to-nawi-purple text-white'
                  : 'glass-effect hover:bg-white/10'
              }`}
            >
              {tab === 'requests' ? 'Design Requests' : 'My Designs'}
            </button>
          ))}
        </div>

        {/* Content */}
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.3 }}
        >
          {activeTab === 'requests' ? (
            <div className="space-y-4">
              {requests.length === 0 ? (
                <div className="glass-effect rounded-2xl p-12 text-center">
                  <DocumentTextIcon className="w-16 h-16 mx-auto mb-4 text-gray-400" />
                  <h3 className="text-xl font-semibold mb-2">No requests yet</h3>
                  <p className="text-gray-400 mb-6">Start by requesting a design service</p>
                  <button
                    onClick={() => navigate('/services')}
                    className="button-primary"
                  >
                    Browse Services
                  </button>
                </div>
              ) : (
                requests.map((request, index) => (
                  <motion.div
                    key={request.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3, delay: index * 0.05 }}
                    className="glass-effect rounded-2xl p-6"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          <h3 className="text-xl font-semibold">{request.service_type}</h3>
                          <span className={`px-3 py-1 rounded-full text-sm font-medium flex items-center gap-1 ${getStatusColor(request.status)}`}>
                            {getStatusIcon(request.status)}
                            {request.status.replace('_', ' ')}
                          </span>
                        </div>
                        <p className="text-gray-400 mb-4 line-clamp-2">{request.project_description}</p>
                        <div className="flex items-center space-x-4 text-sm text-gray-400">
                          <span>Created: {new Date(request.created_at).toLocaleDateString()}</span>
                          {request.deadline && (
                            <span>Deadline: {new Date(request.deadline).toLocaleDateString()}</span>
                          )}
                        </div>
                      </div>
                      
                      {request.status === 'completed' && (
                        <button className="p-3 rounded-xl glass-effect hover:bg-white/10 transition-colors">
                          <EyeIcon className="w-5 h-5" />
                        </button>
                      )}
                    </div>
                  </motion.div>
                ))
              )}
            </div>
          ) : (
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
              {designs.length === 0 ? (
                <div className="col-span-full glass-effect rounded-2xl p-12 text-center">
                  <FolderIcon className="w-16 h-16 mx-auto mb-4 text-gray-400" />
                  <h3 className="text-xl font-semibold mb-2">No designs yet</h3>
                  <p className="text-gray-400">Your completed designs will appear here</p>
                </div>
              ) : (
                designs.map((design, index) => (
                  <motion.div
                    key={design.id}
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 0.3, delay: index * 0.05 }}
                    whileHover={{ y: -5 }}
                    className="glass-effect rounded-2xl overflow-hidden group"
                  >
                    <div className="aspect-square bg-gradient-to-br from-nawi-blue/20 to-nawi-purple/20 relative">
                      {design.preview_url && (
                        <img
                          src={design.preview_url}
                          alt={design.title}
                          className="w-full h-full object-cover"
                        />
                      )}
                      <div className="absolute inset-0 bg-black/60 opacity-0 group-hover:opacity-100 
                                    transition-opacity flex items-center justify-center space-x-4">
                        <button className="p-3 rounded-full bg-white/20 hover:bg-white/30 transition-colors">
                          <EyeIcon className="w-6 h-6" />
                        </button>
                        <button className="p-3 rounded-full bg-white/20 hover:bg-white/30 transition-colors">
                          <ArrowDownTrayIcon className="w-6 h-6" />
                        </button>
                      </div>
                    </div>
                    <div className="p-4">
                      <h3 className="font-semibold mb-1">{design.title}</h3>
                      <p className="text-sm text-gray-400 mb-2">{design.description}</p>
                      <div className="flex items-center justify-between text-xs text-gray-400">
                        <span>{new Date(design.created_at).toLocaleDateString()}</span>
                        <span>{design.download_count} downloads</span>
                      </div>
                    </div>
                  </motion.div>
                ))
              )}
            </div>
          )}
        </motion.div>
      </div>
    </div>
  )
}

export default Dashboard