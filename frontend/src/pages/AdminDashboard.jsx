import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { useAuth } from '../contexts/AuthContext'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'
import toast from 'react-hot-toast'
import {
  UsersIcon,
  DocumentTextIcon,
  FolderIcon,
  EnvelopeIcon,
  PlusIcon,
  PencilIcon,
  TrashIcon,
  CheckIcon,
  XMarkIcon,
  ArrowUpTrayIcon,
} from '@heroicons/react/24/outline'

const AdminDashboard = () => {
  const { user, isAdmin } = useAuth()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState('requests')
  const [requests, setRequests] = useState([])
  const [messages, setMessages] = useState([])
  const [portfolio, setPortfolio] = useState([])
  const [services, setServices] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedRequest, setSelectedRequest] = useState(null)

  useEffect(() => {
    if (!isAdmin) {
      navigate('/')
      toast.error('Admin access required')
      return
    }
    fetchAdminData()
  }, [isAdmin, navigate])

  const fetchAdminData = async () => {
    try {
      const [requestsRes, messagesRes, portfolioRes, servicesRes] = await Promise.all([
        axios.get('/api/admin/requests'),
        axios.get('/api/admin/messages'),
        axios.get('/api/portfolio'),
        axios.get('/api/services')
      ])
      setRequests(requestsRes.data)
      setMessages(messagesRes.data)
      setPortfolio(portfolioRes.data)
      setServices(servicesRes.data)
    } catch (error) {
      toast.error('Failed to load admin data')
    } finally {
      setLoading(false)
    }
  }

  const updateRequestStatus = async (requestId, status, notes) => {
    try {
      await axios.patch(`/api/admin/requests/${requestId}`, { status, notes })
      toast.success('Request updated successfully')
      fetchAdminData()
      setSelectedRequest(null)
    } catch (error) {
      toast.error('Failed to update request')
    }
  }

  const markMessageRead = async (messageId) => {
    try {
      await axios.patch(`/api/admin/messages/${messageId}/read`)
      fetchAdminData()
    } catch (error) {
      console.error('Failed to mark message as read')
    }
  }

  const stats = [
    { label: 'Total Requests', value: requests.length, icon: <DocumentTextIcon className="w-6 h-6" />, color: 'from-blue-500 to-cyan-500' },
    { label: 'Unread Messages', value: messages.filter(m => !m.is_read).length, icon: <EnvelopeIcon className="w-6 h-6" />, color: 'from-purple-500 to-pink-500' },
    { label: 'Portfolio Items', value: portfolio.length, icon: <FolderIcon className="w-6 h-6" />, color: 'from-green-500 to-teal-500' },
    { label: 'Active Services', value: services.length, icon: <UsersIcon className="w-6 h-6" />, color: 'from-orange-500 to-red-500' },
  ]

  const tabs = [
    { id: 'requests', label: 'Design Requests', count: requests.filter(r => r.status === 'pending').length },
    { id: 'messages', label: 'Messages', count: messages.filter(m => !m.is_read).length },
    { id: 'portfolio', label: 'Portfolio' },
    { id: 'services', label: 'Services' },
  ]

  if (loading) {
    return (
      <div className="min-h-screen pt-32 flex items-center justify-center">
        <div className="w-16 h-16 border-4 border-nawi-purple border-t-transparent rounded-full animate-spin" />
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
            <span className="gradient-text">Admin Dashboard</span>
          </h1>
          <p className="text-gray-400">Manage requests, portfolio, and services</p>
        </motion.div>

        {/* Stats */}
        <div className="grid md:grid-cols-4 gap-6 mb-8">
          {stats.map((stat, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.3, delay: index * 0.1 }}
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
        <div className="flex space-x-4 mb-6 overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-6 py-3 rounded-xl font-medium transition-all whitespace-nowrap ${
                activeTab === tab.id
                  ? 'bg-gradient-to-r from-nawi-purple to-pink-500 text-white'
                  : 'glass-effect hover:bg-white/10'
              }`}
            >
              {tab.label}
              {tab.count > 0 && (
                <span className="ml-2 px-2 py-0.5 bg-red-500 text-white text-xs rounded-full">
                  {tab.count}
                </span>
              )}
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
          {/* Design Requests */}
          {activeTab === 'requests' && (
            <div className="space-y-4">
              {requests.map((request) => (
                <motion.div
                  key={request.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="glass-effect rounded-2xl p-6"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <h3 className="text-xl font-semibold mb-2">{request.service_type}</h3>
                      <div className="space-y-1 text-sm text-gray-400">
                        <p>Client: {request.name} ({request.email})</p>
                        <p>Company: {request.company || 'N/A'}</p>
                        <p>Budget: {request.budget_range || 'Not specified'}</p>
                        {request.deadline && <p>Deadline: {new Date(request.deadline).toLocaleDateString()}</p>}
                      </div>
                    </div>
                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                      request.status === 'pending' ? 'bg-yellow-500/20 text-yellow-500' :
                      request.status === 'in_progress' ? 'bg-blue-500/20 text-blue-500' :
                      request.status === 'completed' ? 'bg-green-500/20 text-green-500' :
                      'bg-red-500/20 text-red-500'
                    }`}>
                      {request.status.replace('_', ' ')}
                    </span>
                  </div>
                  
                  <p className="text-gray-300 mb-4">{request.project_description}</p>
                  
                  {request.notes && (
                    <div className="p-3 bg-white/5 rounded-lg mb-4">
                      <p className="text-sm text-gray-400">Admin Notes:</p>
                      <p className="text-sm">{request.notes}</p>
                    </div>
                  )}
                  
                  <div className="flex space-x-2">
                    <button
                      onClick={() => setSelectedRequest(request)}
                      className="px-4 py-2 rounded-lg bg-nawi-purple/20 hover:bg-nawi-purple/30 transition-colors"
                    >
                      Update Status
                    </button>
                    {request.phone && (
                      <a
                        href={`tel:${request.phone}`}
                        className="px-4 py-2 rounded-lg bg-green-500/20 hover:bg-green-500/30 transition-colors"
                      >
                        Call Client
                      </a>
                    )}
                  </div>
                </motion.div>
              ))}
            </div>
          )}

          {/* Messages */}
          {activeTab === 'messages' && (
            <div className="space-y-4">
              {messages.map((message) => (
                <motion.div
                  key={message.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`glass-effect rounded-2xl p-6 ${!message.is_read ? 'border-l-4 border-nawi-blue' : ''}`}
                  onClick={() => !message.is_read && markMessageRead(message.id)}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <h3 className="font-semibold">{message.name}</h3>
                      <p className="text-sm text-gray-400">{message.email}</p>
                    </div>
                    <span className="text-xs text-gray-400">
                      {new Date(message.created_at).toLocaleDateString()}
                    </span>
                  </div>
                  
                  {message.subject && (
                    <p className="font-medium mb-2">{message.subject}</p>
                  )}
                  
                  <p className="text-gray-300">{message.message}</p>
                  
                  <div className="mt-4 flex space-x-2">
                    <a
                      href={`mailto:${message.email}`}
                      className="px-4 py-2 rounded-lg bg-nawi-blue/20 hover:bg-nawi-blue/30 transition-colors text-sm"
                    >
                      Reply
                    </a>
                    {!message.is_read && (
                      <span className="px-3 py-1 rounded-full bg-blue-500/20 text-blue-500 text-xs">
                        New
                      </span>
                    )}
                  </div>
                </motion.div>
              ))}
            </div>
          )}

          {/* Portfolio */}
          {activeTab === 'portfolio' && (
            <div>
              <button className="button-primary mb-6 flex items-center gap-2">
                <PlusIcon className="w-5 h-5" />
                Add Portfolio Item
              </button>
              
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                {portfolio.map((item) => (
                  <motion.div
                    key={item.id}
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="glass-effect rounded-2xl overflow-hidden"
                  >
                    <div className="aspect-square bg-gradient-to-br from-nawi-blue/20 to-nawi-purple/20">
                      {item.image_url && (
                        <img
                          src={item.thumbnail_url || item.image_url}
                          alt={item.title}
                          className="w-full h-full object-cover"
                        />
                      )}
                    </div>
                    <div className="p-4">
                      <h3 className="font-semibold mb-1">{item.title}</h3>
                      <p className="text-sm text-gray-400 mb-3">{item.category}</p>
                      <div className="flex space-x-2">
                        <button className="p-2 rounded-lg bg-white/10 hover:bg-white/20 transition-colors">
                          <PencilIcon className="w-4 h-4" />
                        </button>
                        <button className="p-2 rounded-lg bg-red-500/20 hover:bg-red-500/30 transition-colors">
                          <TrashIcon className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          )}

          {/* Services */}
          {activeTab === 'services' && (
            <div>
              <button className="button-primary mb-6 flex items-center gap-2">
                <PlusIcon className="w-5 h-5" />
                Add Service
              </button>
              
              <div className="grid md:grid-cols-2 gap-6">
                {services.map((service) => (
                  <motion.div
                    key={service.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="glass-effect rounded-2xl p-6"
                  >
                    <h3 className="text-xl font-semibold mb-2">{service.title}</h3>
                    <p className="text-gray-400 mb-4">{service.description}</p>
                    <div className="flex items-center justify-between">
                      <span className="text-lg font-bold gradient-text">{service.price_range}</span>
                      <div className="flex space-x-2">
                        <button className="p-2 rounded-lg bg-white/10 hover:bg-white/20 transition-colors">
                          <PencilIcon className="w-4 h-4" />
                        </button>
                        <button className="p-2 rounded-lg bg-red-500/20 hover:bg-red-500/30 transition-colors">
                          <TrashIcon className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          )}
        </motion.div>

        {/* Status Update Modal */}
        {selectedRequest && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setSelectedRequest(null)}
          >
            <motion.div
              initial={{ scale: 0.9 }}
              animate={{ scale: 1 }}
              className="glass-effect rounded-2xl p-6 max-w-md w-full"
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="text-xl font-semibold mb-4">Update Request Status</h3>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Status</label>
                  <select
                    className="w-full px-4 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-nawi-purple focus:outline-none"
                    defaultValue={selectedRequest.status}
                    onChange={(e) => setSelectedRequest({...selectedRequest, status: e.target.value})}
                  >
                    <option value="pending">Pending</option>
                    <option value="in_progress">In Progress</option>
                    <option value="completed">Completed</option>
                    <option value="cancelled">Cancelled</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium mb-2">Admin Notes</label>
                  <textarea
                    className="w-full px-4 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-nawi-purple focus:outline-none resize-none"
                    rows={3}
                    defaultValue={selectedRequest.notes}
                    onChange={(e) => setSelectedRequest({...selectedRequest, notes: e.target.value})}
                  />
                </div>
                
                <div className="flex space-x-3">
                  <button
                    onClick={() => updateRequestStatus(selectedRequest.id, selectedRequest.status, selectedRequest.notes)}
                    className="button-primary flex-1"
                  >
                    Update
                  </button>
                  <button
                    onClick={() => setSelectedRequest(null)}
                    className="px-6 py-2 rounded-full border border-white/20 hover:bg-white/10 transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </div>
    </div>
  )
}

export default AdminDashboard