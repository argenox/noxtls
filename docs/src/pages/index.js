import { Redirect } from '@docusaurus/router';

/**
 * Site root: redirect to latest docs intro so visitors land on the current release.
 * /docs (without a version path) always serves the first version in versions.json (e.g. 0.2.1).
 */
export default function Home() {
  return <Redirect to="/docs/intro" />;
}
