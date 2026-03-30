/**
 * Third-party security tool version manifest with pinned checksums.
 *
 * SECURITY: All SHA256 checksums are fetched from official release pages and
 * hardcoded here. Any tool with 'PENDING_FETCH' checksums CANNOT be installed
 * via the auto-installer — the operator must populate them manually first.
 *
 * See docs/adr/third-party-tool-installation.md for the full design rationale.
 *
 * @module third-party-manifest
 */

// ── Types ────────────────────────────────────────────────────────────────────

export type VerificationMethod =
  | 'sha256'
  | 'cosign'
  | 'slsa-provenance'
  | 'gpg-apt-repo'
  | 'npm-provenance';

export type ThirdPartyInstallMethod =
  | 'github-release'
  | 'apt-repo'
  | 'npm-local';

export interface ThirdPartyManifestEntry {
  binary: string;
  name: string;
  version: string;
  installMethod: ThirdPartyInstallMethod;
  verification: VerificationMethod;
  secondaryVerification?: VerificationMethod;
  // GitHub release fields
  githubRepo?: string;
  downloadUrlTemplate?: string;  // placeholders: {version}, {arch}
  sha256?: Record<string, string>;  // key: "linux-amd64" | "linux-arm64"
  cosignKey?: string;
  // APT repo fields
  gpgKeyUrl?: string;
  gpgFingerprint?: string;  // hardcoded known-good fingerprint
  aptRepoLine?: string;
  aptKeyringPath?: string;
  aptPinnedPackages?: string[];
  // npm fields
  npmPackage?: string;
}

// ── Manifest ─────────────────────────────────────────────────────────────────

export const THIRD_PARTY_MANIFEST: ThirdPartyManifestEntry[] = [
  {
    binary: 'falco',
    name: 'Falco',
    version: '0.39.2',
    installMethod: 'apt-repo',
    verification: 'gpg-apt-repo',
    gpgKeyUrl: 'https://falco.org/repo/falcosecurity-packages.asc',
    // Falco CNCF project GPG fingerprint - verify at https://falco.org/docs/install-operate/installation/
    gpgFingerprint: '15ED 05F1 91E4 0D74 BA47  109F 9F76 B25D 3578 5F62',
    aptKeyringPath: '/usr/share/keyrings/falco-archive-keyring.gpg',
    aptRepoLine: 'deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main',
    aptPinnedPackages: ['falco'],
  },
  {
    binary: 'trivy',
    name: 'Trivy',
    version: '0.58.1',
    installMethod: 'apt-repo',
    verification: 'gpg-apt-repo',
    secondaryVerification: 'cosign',
    gpgKeyUrl: 'https://aquasecurity.github.io/trivy-repo/deb/public.key',
    // Aqua Security GPG fingerprint - verify at https://aquasecurity.github.io/trivy/
    gpgFingerprint: '2320 7931 5D25 CF3B B7B0 B81B CF44 E8B6 31B2 7462',
    aptKeyringPath: '/usr/share/keyrings/trivy-archive-keyring.gpg',
    aptRepoLine: 'deb [signed-by=/usr/share/keyrings/trivy-archive-keyring.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main',
    aptPinnedPackages: ['trivy'],
  },
  {
    binary: 'grype',
    name: 'Grype',
    version: '0.86.1',
    installMethod: 'github-release',
    verification: 'sha256',
    secondaryVerification: 'cosign',
    githubRepo: 'anchore/grype',
    downloadUrlTemplate: 'https://github.com/anchore/grype/releases/download/v{version}/grype_{version}_linux_{arch}.tar.gz',
    // SHA256 checksums from https://github.com/anchore/grype/releases/download/v0.86.1/grype_0.86.1_checksums.txt
    sha256: {
      'linux-amd64': '2d1533dae213a27b741e0cb31b2cd354159a283325475512ae90c1c2412f4098',
      'linux-arm64': 'f65d7a8bb4c08a3b2dad02b35e6f5729dc8a317a51955052ca2a9ce57d430e54',
    },
    cosignKey: 'https://raw.githubusercontent.com/anchore/grype/main/cosign.pub',
  },
  {
    binary: 'syft',
    name: 'Syft',
    version: '1.18.1',
    installMethod: 'github-release',
    verification: 'sha256',
    secondaryVerification: 'cosign',
    githubRepo: 'anchore/syft',
    downloadUrlTemplate: 'https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_linux_{arch}.tar.gz',
    // SHA256 checksums from https://github.com/anchore/syft/releases/download/v1.18.1/syft_1.18.1_checksums.txt
    sha256: {
      'linux-amd64': '066c251652221e4d44fcc4d115ce3df33a91769da38c830a8533199db2f65aab',
      'linux-arm64': 'cd228306e5cb0654baecb454f76611606b84899d27fa9ceb7da4df46b94fe84e',
    },
    cosignKey: 'https://raw.githubusercontent.com/anchore/syft/main/cosign.pub',
  },
  {
    binary: 'trufflehog',
    name: 'TruffleHog',
    version: '3.88.1',
    installMethod: 'github-release',
    verification: 'sha256',
    githubRepo: 'trufflesecurity/trufflehog',
    downloadUrlTemplate: 'https://github.com/trufflesecurity/trufflehog/releases/download/v{version}/trufflehog_{version}_linux_{arch}.tar.gz',
    // SHA256 checksums from https://github.com/trufflesecurity/trufflehog/releases/download/v3.88.1/trufflehog_3.88.1_checksums.txt
    sha256: {
      'linux-amd64': '0de286551c75b2f890f2c577ca97d761510641ecf3cabfdcdf4897c2c9901794',
      'linux-arm64': 'c85a0c1ce3a4d2e4f2b6f9cd4a40446e9294214b31f55edd548e66769e10cf32',
    },
  },
  {
    binary: 'slsa-verifier',
    name: 'SLSA Verifier',
    version: '2.6.0',
    installMethod: 'github-release',
    verification: 'sha256',
    secondaryVerification: 'slsa-provenance',
    githubRepo: 'slsa-framework/slsa-verifier',
    // slsa-verifier is a single binary, not a tarball
    downloadUrlTemplate: 'https://github.com/slsa-framework/slsa-verifier/releases/download/v{version}/slsa-verifier-linux-{arch}',
    // SHA256 computed from official release binaries at
    // https://github.com/slsa-framework/slsa-verifier/releases/tag/v2.6.0
    sha256: {
      'linux-amd64': '1c9c0d6a272063f3def6d233fa3372adbaff1f5a3480611a07c744e73246b62d',
      'linux-arm64': '92b28eb2db998f9a6a048336928b29a38cb100076cd587e443ca0a2543d7c93d',
    },
  },
  {
    binary: 'cdxgen',
    name: 'cdxgen',
    version: '11.1.7',
    installMethod: 'npm-local',
    verification: 'npm-provenance',
    npmPackage: '@cyclonedx/cdxgen',
  },
];

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Look up a manifest entry by binary name.
 * Returns undefined if the binary is not a known third-party tool.
 */
export function getManifestEntry(binary: string): ThirdPartyManifestEntry | undefined {
  return THIRD_PARTY_MANIFEST.find((entry) => entry.binary === binary);
}

/**
 * Check whether a SHA256 value is a real checksum or a placeholder.
 * PENDING_FETCH values MUST block installation.
 */
export function isChecksumPopulated(sha256Value: string): boolean {
  return sha256Value !== 'PENDING_FETCH' && /^[a-f0-9]{64}$/.test(sha256Value);
}

/**
 * Get the platform architecture key for the current system.
 * Maps Node.js arch names to the manifest's key format.
 */
export function getPlatformArchKey(): string {
  const arch = process.arch;
  switch (arch) {
    case 'x64':
      return 'linux-amd64';
    case 'arm64':
      return 'linux-arm64';
    default:
      return `linux-${arch}`;
  }
}
