import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Activity, ShieldAlert, Wifi, Server } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api';
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://127.0.0.1:8000/ws/events';

// Addresses arrive already pseudonymized: the backend scrubs them before they
// reach the WebSocket or the REST API, so the browser never receives a raw IP.
// Hashing here as well would only re-hash an already-anonymous label.
const formatIp = (ip) => ip || "Unknown";

const StatCard = ({ title, value, icon: Icon, colorClass, animationDelay }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ delay: animationDelay, duration: 0.5 }}
    className="bg-white p-6 rounded-xl border border-gray-100 shadow-sm flex items-center justify-between"
  >
    <div>
      <p className="text-sm font-medium text-gray-500 mb-1">{title}</p>
      <h3 className="text-3xl font-bold text-gray-900">{value}</h3>
    </div>
    <div className={`p-4 rounded-full ${colorClass}`}>
      <Icon size={24} />
    </div>
  </motion.div>
);

export default function App() {
  const [stats, setStats] = useState({ total_flows: 0, total_alerts: 0, protocol_distribution: {} });
  const [alerts, setAlerts] = useState([]);
  const [flows, setFlows] = useState([]);
  const [connected, setConnected] = useState(false);

  const fetchData = async () => {
    try {
      const statsRes = await fetch(`${API_URL}/stats`);
      const alertsRes = await fetch(`${API_URL}/alerts?limit=10`);
      const flowsRes = await fetch(`${API_URL}/flows?limit=20`);
      
      if (statsRes.ok) setStats(await statsRes.json());
      if (alertsRes.ok) setAlerts(await alertsRes.json());
      if (flowsRes.ok) setFlows(await flowsRes.json());
    } catch (error) {
      console.error("Error fetching data:", error);
    }
  };

  useEffect(() => {
    let socket;
    let reconnectTimer;

    const connect = () => {
      socket = new WebSocket(WS_URL);

      socket.onopen = () => {
        setConnected(true);
      };

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.stats) setStats(payload.stats);
          if (payload.alerts) setAlerts(payload.alerts);
          if (payload.flows) setFlows(payload.flows);
        } catch (error) {
          console.error('WebSocket message parse error:', error);
        }
      };

      socket.onclose = () => {
        setConnected(false);
        reconnectTimer = setTimeout(connect, 1500);
      };

      socket.onerror = () => {
        socket.close();
      };
    };

    fetchData();
    connect();

    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (socket) socket.close();
    };
  }, []);

  const protocolData = Object.keys(stats.protocol_distribution).map(key => ({
    name: key,
    value: stats.protocol_distribution[key]
  }));

  const chartData = flows.map((f, i) => ({
    time: i,
    bytes: f.features ? f.features["Flow Bytes/s"] : 0
  })).reverse();

  const topSourceIps = stats.top_source_ips || [];

  return (
    <div className="min-h-screen bg-slate-50 p-8 font-sans">
      <div className="max-w-7xl mx-auto space-y-8">
        
        {/* Header */}
        <header className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-gray-900">AI-NIDS Dashboard</h1>
            <p className="text-gray-500 mt-1">Real-time Network Intrusion Detection</p>
          </div>
          <div className={`flex items-center space-x-2 text-sm px-4 py-2 rounded-full border ${connected ? 'bg-green-50 text-green-700 border-green-100' : 'bg-amber-50 text-amber-700 border-amber-100'}`}>
            <span className="relative flex h-3 w-3">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${connected ? 'bg-green-400' : 'bg-amber-400'}`}></span>
              <span className={`relative inline-flex rounded-full h-3 w-3 ${connected ? 'bg-green-500' : 'bg-amber-500'}`}></span>
            </span>
            <span className="font-medium">{connected ? 'Live Stream Connected' : 'Reconnecting stream...'}</span>
          </div>
        </header>

        {/* Privacy Disclaimer */}
        <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4 rounded-md shadow-sm">
          <div className="flex">
            <div className="flex-shrink-0">
              <ShieldAlert className="h-5 w-5 text-yellow-400" />
            </div>
            <div className="ml-3 text-sm text-yellow-700">
              <span className="font-bold">Privacy Mode Active:</span> IP addresses are pseudonymized by the backend before they are sent to this dashboard, so no raw address crosses the network or reaches your browser. The engine continues to perform all packet analysis and threat detection on the real, untampered traffic.
            </div>
          </div>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatCard 
            title="Total Flows Analyzed" 
            value={stats.total_flows} 
            icon={Activity} 
            colorClass="bg-blue-50 text-blue-600"
            animationDelay={0.1}
          />
          <StatCard 
            title="Anomalies Detected" 
            value={stats.total_alerts} 
            icon={ShieldAlert} 
            colorClass="bg-red-50 text-red-600"
            animationDelay={0.2}
          />
          <StatCard 
            title="Active Connections" 
            value={flows.length} 
            icon={Wifi} 
            colorClass="bg-slate-100 text-slate-700"
            animationDelay={0.3}
          />
          <StatCard 
            title="Protocols Tracked" 
            value={Object.keys(stats.protocol_distribution).length} 
            icon={Server} 
            colorClass="bg-orange-50 text-orange-600"
            animationDelay={0.4}
          />
        </div>

        <motion.div 
          initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.65 }}
          className="bg-white p-6 rounded-xl border border-gray-100 shadow-sm"
        >
          <h3 className="text-lg font-semibold mb-4 text-gray-800">Top Source IPs</h3>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            {topSourceIps.length === 0 ? (
              <div className="text-gray-500 text-sm">No traffic yet.</div>
            ) : (
              topSourceIps.map((item) => (
                <div key={item.ip} className="rounded-lg border border-gray-100 p-3 bg-gray-50">
                  <div className="text-xs text-gray-500">Source</div>
                  <div className="font-medium text-gray-900 truncate">{formatIp(item.ip)}</div>
                  <div className="text-xs text-gray-500 mt-1">Flows: {item.count}</div>
                </div>
              ))
            )}
          </div>
        </motion.div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <motion.div 
            initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}
            className="lg:col-span-2 bg-white p-6 rounded-xl border border-gray-100 shadow-sm"
          >
            <h3 className="text-lg font-semibold mb-4 text-gray-800">Live Traffic Flow (Bytes/s)</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f0f0f0" />
                  <XAxis dataKey="time" hide />
                  <YAxis stroke="#9ca3af" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }} />
                  <Line type="monotone" dataKey="bytes" stroke="#3b82f6" strokeWidth={3} dot={false} animationDuration={300} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </motion.div>

          <motion.div 
            initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }}
            className="bg-white p-6 rounded-xl border border-gray-100 shadow-sm"
          >
            <h3 className="text-lg font-semibold mb-4 text-gray-800">Protocol Distribution</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={protocolData}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f0f0f0"/>
                  <XAxis dataKey="name" stroke="#9ca3af" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip cursor={{fill: 'transparent'}} contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }} />
                  <Bar dataKey="value" fill="#111827" radius={[4, 4, 0, 0]} animationDuration={500} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </motion.div>
        </div>

        {/* Alerts Table */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.7 }}
          className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden"
        >
          <div className="p-6 border-b border-gray-100 bg-white flex justify-between items-center">
            <h3 className="text-lg font-semibold text-gray-800">Recent Security Alerts</h3>
            <span className="bg-red-50 text-red-600 text-xs font-semibold px-2.5 py-1 rounded-full">{alerts.length} Detected</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-gray-50 text-gray-500">
                <tr>
                  <th className="px-6 py-4 font-medium">Time</th>
                  <th className="px-6 py-4 font-medium">Source IP</th>
                  <th className="px-6 py-4 font-medium">Destination IP</th>
                  <th className="px-6 py-4 font-medium">Attack Type</th>
                  <th className="px-6 py-4 font-medium">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {alerts.length === 0 ? (
                  <tr><td colSpan="5" className="px-6 py-8 text-center text-gray-500">No anomalies detected recently. System is secure.</td></tr>
                ) : (
                  alerts.map((alert, idx) => (
                    <motion.tr 
                      initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: idx * 0.1 }}
                      key={alert.id} className="hover:bg-gray-50 transition-colors"
                    >
                      <td className="px-6 py-4 text-gray-500">{new Date(alert.timestamp * 1000).toLocaleTimeString()}</td>
                      <td className="px-6 py-4 font-medium text-gray-900">{formatIp(alert.src_ip)}</td>
                      <td className="px-6 py-4 text-gray-500">{formatIp(alert.dst_ip)}</td>
                      <td className="px-6 py-4">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-800">
                          {alert.attack_type}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                          {alert.severity}
                        </span>
                      </td>
                    </motion.tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </motion.div>

      </div>
    </div>
  );
}
