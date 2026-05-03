// @ts-check
// NoxTLS documentation - https://docs.noxtls.com

import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'NoxTLS',
  tagline: 'C crypto and TLS library',
  favicon: 'img/noxtls-logo-25.webp',

  future: {
    v4: true,
  },

  url: 'https://docs.noxtls.com',
  baseUrl: '/',

  onBrokenLinks: 'warn',

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
              { label: 'Crypto API', to: '/docs/api' },
              { label: 'Applications', to: '/docs/applications' },
              { label: 'Release Notes', to: '/docs/release-notes' },
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
