import axios from 'axios'

const API_BASE = '/api'

export const api = {
  // Get all alerts
  getAlerts: async (severity = null, ip = null) => {
    let url = `${API_BASE}/alerts`
    const params = new URLSearchParams()
    if (severity) params.append('severity', severity)
    if (ip) params.append('ip', ip)
    if (params.toString()) url += `?${params.toString()}`
    return axios.get(url)
  },
  
  // Get specific alert
  getAlert: async (id) => {
    return axios.get(`${API_BASE}/alerts/${id}`)
  },
  
  // Delete specific alert
  deleteAlert: async (id) => {
    return axios.delete(`${API_BASE}/alerts/${id}`)
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
  },
  
  // NEW: IP Blocking
  blockIP: async (ip, reason = 'Manual block', duration = 'permanent') => {
    return axios.post(`${API_BASE}/block-ip`, { ip, reason, duration })
  },
  
  // NEW: Unblock IP
  unblockIP: async (ip) => {
    return axios.delete(`${API_BASE}/blocked-ips/${ip}`)
  },
  
  // NEW: Get blocked IPs
  getBlockedIPs: async () => {
    return axios.get(`${API_BASE}/blocked-ips`)
  },
  
  // NEW: IP Investigation
  getIPHistory: async (ip) => {
    return axios.get(`${API_BASE}/ip-history/${ip}`)
  },
  
  // NEW: Action Logs
  getActionLogs: async (limit = 50) => {
    return axios.get(`${API_BASE}/actions/logs?limit=${limit}`)
  },
  
  // NEW: Model Info
  getModelInfo: async () => {
    return axios.get(`${API_BASE}/model/info`)
  }
}