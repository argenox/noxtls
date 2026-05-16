// @ts-check
// NoxTLS documentation - https://docs.noxtls.com

import {themes as prismThemes} from 'prism-react-renderer';
import {
  DEFAULT_DESCRIPTION,
  DEFAULT_KEYWORDS,
  DEFAULT_TITLE,
  OG_IMAGE,
  SITE_NAME,
  SITE_URL,
} from './seo-defaults';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: DEFAULT_TITLE,
  tagline: 'C crypto and TLS/DTLS library for embedded systems',
  favicon: 'img/noxtls-logo-25.webp',

  future: {
    v4: true,
  },

  url: SITE_URL,
  baseUrl: '/',

  onBrokenLinks: 'warn',
  onBrokenAnchors: 'warn',
  trailingSlash: false,

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: './sidebars.js',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      image: OG_IMAGE,
      metadata: [
        {name: 'description', content: DEFAULT_DESCRIPTION},
        {name: 'keywords', content: DEFAULT_KEYWORDS},
        {name: 'author', content: 'Argenox Technologies LLC'},
        {name: 'robots', content: 'index, follow'},
        {property: 'og:type', content: 'website'},
        {property: 'og:site_name', content: SITE_NAME},
        {property: 'og:locale', content: 'en_US'},
        {name: 'twitter:card', content: 'summary_large_image'},
      ],
      navbar: {
        title: 'NoxTLS',
        logo: {
          alt: 'NoxTLS',
          src: 'img/noxtls-logo-25.webp',
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'docsSidebar',
            position: 'left',
            label: 'Documentation',
          },
          {
            type: 'docsVersionDropdown',
            position: 'right',
            dropdownItemsBefore: [],
            dropdownItemsAfter: [
              { to: 'https://github.com/argenox/noxtls/releases', label: 'All releases' },
            ],
          },
          {
            href: 'https://github.com/argenox/noxtls',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Documentation',
            items: [
              { label: 'Introduction', to: '/docs/intro' },
              { label: 'Getting Started', to: '/docs/getting-started' },
              { label: 'Architecture', to: '/docs/architecture' },
              { label: 'Security', to: '/docs/security' },
              { label: 'Security Reporting', to: '/docs/security-reporting' },
              { label: 'Crypto API', to: '/docs/api' },
              { label: 'Applications', to: '/docs/applications' },
              { label: 'Release Notes', to: '/docs/release-notes' },
              { label: 'Project', to: '/docs/project' },
              { label: 'Contributing', to: '/docs/contributing' },
            ],
          },
          {
            title: 'Get the Code',
            items: [
              { label: 'Build from source', to: '/docs/getting-started' },
              { label: 'GitHub', href: 'https://github.com/argenox/noxtls' },
            ],
          },
          {
            title: 'Community',
            items: [
              { label: 'GitHub', href: 'https://github.com/argenox/noxtls' },
              { label: 'Contact', href: 'mailto:info@argenox.com' },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} Argenox Technologies LLC.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['c'],
      },
    }),
};

export default config;
