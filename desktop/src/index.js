import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);

// Hide boot screen once React has mounted
const bootScreen = document.getElementById('boot-screen');
if (bootScreen) bootScreen.style.display = 'none';
if (window.__clearBootInterval) window.__clearBootInterval();
