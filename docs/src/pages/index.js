import React from 'react';
import Link from '@docusaurus/Link';

/**
 * Site root: redirect to latest docs intro so visitors land on the current release.
 * /docs (without a version path) serves the current documentation set (0.2.4).
 */
export default function Home() {
  return (
    <main style={{ maxWidth: 900, margin: '0 auto', padding: '3rem 1rem' }}>
      <h1>NoxTLS Documentation</h1>
      <p>
        NoxTLS is a C cryptography and TLS/DTLS library for embedded and systems software.
        The docs cover classical and post-quantum cryptography, protocol APIs, configuration,
        and deployment guidance.
      </p>

      <h2>Start here</h2>
      <ul>
        <li><Link to="/docs/next/getting-started">Getting Started</Link></li>
        <li><Link to="/docs/next/configuration-guide">Configuration Guide</Link></li>
        <li><Link to="/docs/next/tls">TLS Component</Link></li>
        <li><Link to="/docs/next/api">Crypto API</Link></li>
      </ul>

      <h2>Post-quantum</h2>
      <ul>
        <li><Link to="/docs/next/quantum-crypto">Quantum crypto overview</Link></li>
        <li><Link to="/docs/next/api/mlkem">ML-KEM API</Link></li>
        <li><Link to="/docs/next/api/mldsa">ML-DSA API</Link></li>
        <li><Link to="/docs/next/api/tls13_pqc">TLS 1.3 PQC integration</Link></li>
      </ul>

      <h2>Project and security</h2>
      <ul>
        <li><Link to="/docs/next/project">Project</Link></li>
        <li><Link to="/docs/next/contributing">Contributing</Link></li>
        <li><Link to="/docs/next/security-reporting">Security Reporting</Link></li>
        <li><Link to="/docs/next/release-notes">Release Notes</Link></li>
      </ul>
    </main>
  );
}
