import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import './index.css'
import Layout from './components/Layout'
import HomePage from './pages/HomePage'
import SimulationPage from './pages/SimulationPage'
import AgentsPage from './pages/AgentsPage'
import AnalyticsPage from './pages/AnalyticsPage'
import DocsPage from './pages/DocsPage'
import AboutPage from './pages/AboutPage'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<HomePage />} />
          <Route path="/simulation" element={<SimulationPage />} />
          <Route path="/agents" element={<AgentsPage />} />
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/docs" element={<DocsPage />} />
          <Route path="/about" element={<AboutPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </StrictMode>,
)
