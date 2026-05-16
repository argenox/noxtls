import React from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';

export default function Home() {
  return (
    <Layout title="NoxTLS Documentation" description="C cryptography and TLS/DTLS library documentation">
      <main style={{ maxWidth: 900, margin: '0 auto', padding: '3rem 1rem' }}>
        <h1>NoxTLS Documentation</h1>
        <p>
          NoxTLS is a C cryptography and TLS/DTLS library for embedded and systems software.
          The docs cover classical and post-quantum cryptography, protocol APIs, configuration,
          and deployment guidance.
        </p>

        <h2>Start here</h2>
        <ul>
          <li><Link to="/docs/getting-started">Getting Started</Link></li>
          <li><Link to="/docs/configuration-guide">Configuration Guide</Link></li>
          <li><Link to="/docs/tls">TLS Component</Link></li>
          <li><Link to="/docs/api">Crypto API</Link></li>
        </ul>

        <h2>Post-quantum</h2>
        <ul>
          <li><Link to="/docs/quantum-crypto">Quantum crypto overview</Link></li>
          <li><Link to="/docs/api/mlkem">ML-KEM API</Link></li>
          <li><Link to="/docs/api/mldsa">ML-DSA API</Link></li>
          <li><Link to="/docs/api/tls13_pqc">TLS 1.3 PQC integration</Link></li>
        </ul>

        <h2>Project and security</h2>
        <ul>
          <li><Link to="/docs/project">Project</Link></li>
          <li><Link to="/docs/contributing">Contributing</Link></li>
          <li><Link to="/docs/security-reporting">Security Reporting</Link></li>
          <li><Link to="/docs/release-notes">Release Notes</Link></li>
        </ul>
      </main>
    </Layout>
  );
}
