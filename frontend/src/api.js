import axios from 'axios'

const API_BASE = '/api'

export const api = {
  // Existing endpoints
  getAlerts: async (severity = null, ip = null) => {
    let url = `${API_BASE}/alerts`
    const params = new URLSearchParams()
    if (severity) params.append('severity', severity)
    if (ip) params.append('ip', ip)
    if (params.toString()) url += `?${params.toString()}`
    return axios.get(url)
  },
  
  getAlert: async (id) => {
    return axios.get(`${API_BASE}/alerts/${id}`)
  },
  
  deleteAlert: async (id) => {
    return axios.delete(`${API_BASE}/alerts/${id}`)
  },
  
  getStats: async () => {
    return axios.get(`${API_BASE}/stats`)
  },
  
  clearAlerts: async () => {
    return axios.delete(`${API_BASE}/alerts`)
  },
  
  sendEvent: async (event) => {
    return axios.post(`${API_BASE}/events`, event)
  },
  
  health: async () => {
    return axios.get('/health')
  },
  
  // NEW: IP Blocking
  blockIP: async (ip, reason = 'Manual block', duration = 'permanent') => {
    return axios.post(`${API_BASE}/block-ip`, { ip, reason, duration })
  },
  
  unblockIP: async (ip) => {
    return axios.delete(`${API_BASE}/blocked-ips/${ip}`)
  },
  
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
  }
}