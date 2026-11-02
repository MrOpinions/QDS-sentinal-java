import React, { Suspense, lazy } from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Landing from './landing/Landing'
import './styles/global.css'

// The dashboard pulls in plotly and the whole chart stack. Landing visitors
// should not pay for it, so it loads only when /dashboard is opened.
const App = lazy(() => import('./App'))

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route
          path="/dashboard"
          element={
            <Suspense fallback={<div className="loading-row">Loading the console…</div>}>
              <App />
            </Suspense>
          }
        />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
)
