import axios from 'axios'

const API_BASE = '/api'

export const api = {
  // Get all alerts
  getAlerts: async (severity = null) => {
    const url = severity ? `${API_BASE}/alerts?severity=${severity}` : `${API_BASE}/alerts`
    return axios.get(url)
  },
  
  // Get specific alert
  getAlert: async (id) => {
    return axios.get(`${API_BASE}/alerts/${id}`)
  },
  
  // Get statistics
  getStats: async () => {
    return axios.get(`${API_BASE}/stats`)
  },
  
  // Clear all alerts
  clearAlerts: async () => {
    return axios.delete(`${API_BASE}/alerts`)
  },
  
  // Send event (for testing)
  sendEvent: async (event) => {
    return axios.post(`${API_BASE}/events`, event)
  },
  
  // Health check
  health: async () => {
    return axios.get('/health')
  }
}
