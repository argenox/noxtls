import { Redirect } from '@docusaurus/router';

/**
 * Site root: redirect to latest docs intro so visitors land on the current release.
 * /docs (without a version path) serves the current documentation set (0.2.4).
 */
export default function Home() {
  return <Redirect to="/docs/intro" />;
}
