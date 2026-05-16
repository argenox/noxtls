import Head from '@docusaurus/Head';
import {Redirect} from '@docusaurus/router';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

const HOME_DESCRIPTION =
  'Official NoxTLS documentation: TLS 1.2/1.3, DTLS, post-quantum crypto, and the full C API for embedded secure connectivity.';

export default function Home() {
  const {siteConfig} = useDocusaurusContext();
  const canonical = `${siteConfig.url}/docs/intro`;

  return (
    <>
      <Head>
        <title>{siteConfig.title} | TLS &amp; DTLS for Embedded C</title>
        <meta name="description" content={HOME_DESCRIPTION} />
        <meta name="robots" content="index, follow" />
        <link rel="canonical" href={canonical} />
        <meta property="og:title" content={`${siteConfig.title} | TLS & DTLS for Embedded C`} />
        <meta property="og:description" content={HOME_DESCRIPTION} />
        <meta property="og:url" content={canonical} />
        <meta property="og:type" content="website" />
        <meta name="twitter:card" content="summary" />
        <meta name="twitter:title" content={`${siteConfig.title} | TLS & DTLS for Embedded C`} />
        <meta name="twitter:description" content={HOME_DESCRIPTION} />
      </Head>
      <Redirect to="/docs/intro" />
    </>
  );
}
