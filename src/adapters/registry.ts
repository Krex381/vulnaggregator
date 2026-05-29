import { registerSource } from '../poller/index.js'
import { nvdAdapter } from './nvd.js'
import { cisaAdapter } from './cisa.js'
import { msrcAdapter } from './msrc.js'
import { githubAdapter } from './github.js'
import { redhatAdapter } from './redhat.js'
import { ubuntuAdapter } from './ubuntu.js'
import { debianAdapter } from './debian.js'
import { ciscoAdapter } from './cisco.js'
import { kubernetesAdapter } from './kubernetes.js'
import { certAdapter } from './cert.js'

import { createRssAdapter } from './rss.js'
import { createScraperAdapter } from './scraper.js'

export function registerAllSources(): void {
  registerSource(nvdAdapter)
  registerSource(cisaAdapter)
  registerSource(msrcAdapter)
  registerSource(githubAdapter)
  registerSource(redhatAdapter)
  registerSource(ubuntuAdapter)
  registerSource(debianAdapter)
  registerSource(ciscoAdapter)
  registerSource(kubernetesAdapter)
  registerSource(certAdapter)

  const rssConfigs = [
    { name: 'Fortinet', url: 'https://filestore.fortinet.com/fortiguard/rss/ir.xml', vendor: 'Fortinet', severity: 'HIGH' as const },
    { name: 'Project Zero', url: 'https://googleprojectzero.blogspot.com/atom.xml', vendor: 'Google', severity: 'HIGH' as const },
    { name: 'Hacker News', url: 'https://hnrss.org/newest?q=CVE', vendor: 'Hacker News', severity: 'MEDIUM' as const },
    { name: 'Bleeping Computer', url: 'https://www.bleepingcomputer.com/feed/', vendor: 'Bleeping Computer', severity: 'MEDIUM' as const },
    { name: 'Juniper', url: 'https://support.juniper.net/feeds/security-advisories/', vendor: 'Juniper', severity: 'HIGH' as const },
    { name: 'Linux Kernel', url: 'https://lore.kernel.org/linux-cve-announce/atom.xml', vendor: 'Linux', severity: 'HIGH' as const },
    { name: 'WordPress', url: 'https://wordpress.org/news/category/security/feed/', vendor: 'WordPress', severity: 'MEDIUM' as const },
    { name: 'GitLab', url: 'https://about.gitlab.com/security-releases.xml', vendor: 'GitLab', severity: 'HIGH' as const },
    { name: 'PHP', url: 'https://www.php.net/releases/feed.php', vendor: 'PHP Group', severity: 'MEDIUM' as const },
    { name: 'Exploit-DB', url: 'https://feeds.feedburner.com/exploitdb', vendor: 'Exploit Database', severity: 'CRITICAL' as const },
  ]

  for (const cfg of rssConfigs) {
    const group = (cfg.name === 'Fortinet' || cfg.name === 'Project Zero' || cfg.name === 'Hacker News' ||
                   cfg.name === 'Bleeping Computer' || cfg.name === 'Exploit-DB')
      ? 'fast' as const
      : cfg.name === 'Oracle CPU' ? 'slow' as const : 'medium' as const
    registerSource(createRssAdapter({ ...cfg, group }))
  }

  const scraperConfigs = [
    { name: 'Oracle CPU', url: 'https://www.oracle.com/security-alerts/', vendor: 'Oracle', itemSelector: 'table tr td a, .cpu-item a, .alert-item a', severity: 'HIGH' as const },
    { name: 'Mozilla', url: 'https://www.mozilla.org/en-US/security/advisories/', vendor: 'Mozilla', itemSelector: '.advisory-list li, .mzp-c-advisory-item, .c-advisory-list li, .c-advisory-item', titleSelector: 'a', severity: 'HIGH' as const },
    { name: 'OpenSSL', url: 'https://www.openssl.org/news/vulnerabilities.html', vendor: 'OpenSSL', itemSelector: '#content li, .entry ul li, main li', titleSelector: 'a', cveFromText: true, severity: 'HIGH' as const },
    { name: 'Adobe Security', url: 'https://helpx.adobe.com/security.html', vendor: 'Adobe', itemSelector: '.security-bulletin-item', titleSelector: 'h3', severity: 'HIGH' as const },
    { name: 'Apple Security', url: 'https://support.apple.com/en-us/HT201222', vendor: 'Apple', itemSelector: '.table--security-content tr', titleSelector: 'td:first-child', severity: 'HIGH' as const },
    { name: 'SUSE Security', url: 'https://www.suse.com/support/update/', vendor: 'SUSE', itemSelector: '.update-item', titleSelector: 'a', severity: 'HIGH' as const },
    { name: 'Apache Security', url: 'https://www.apache.org/security/', vendor: 'Apache', itemSelector: 'li a', severity: 'HIGH' as const },
    { name: 'VMware Security', url: 'https://www.vmware.com/security/advisories.html', vendor: 'VMware', itemSelector: '.advisory-item', titleSelector: 'a', severity: 'HIGH' as const },
    { name: 'Docker Security', url: 'https://www.docker.com/blog/category/security/', vendor: 'Docker', itemSelector: 'article', titleSelector: 'h2 a', severity: 'HIGH' as const },
  ]

  for (const cfg of scraperConfigs) {
    const group = cfg.name === 'Mozilla' ? 'medium' as const : 'slow' as const
    registerSource(createScraperAdapter({ ...cfg, group }))
  }
}
