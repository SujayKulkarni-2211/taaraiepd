import React from 'react';
import ClientDashboard from './ClientDashboard';

export default function MultiClientTab({ onFocusClient }) {
  return (
    <ClientDashboard
      onClientSelected={(client) => onFocusClient && onFocusClient(client)}
      onAddNew={() => {}}
      activeClientId={null}
      onDemoStart={null}
    />
  );
}
