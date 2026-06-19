import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadModule } from './helpers/load-module.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcPath = join(__dirname, '../assets/js/security-analyzer.js');

let SA;
before(() => {
    SA = loadModule(srcPath, 'SecurityAnalyzer');
});

// --- evaluatePortRisk ---

describe('evaluatePortRisk — par numéro de port', () => {
    it('Telnet (23) → critical', () => assert.equal(SA.evaluatePortRisk(23, ''), 'critical'));
    it('Modbus (502) → critical', () => assert.equal(SA.evaluatePortRisk(502, ''), 'critical'));
    it('Siemens S7 (102) → critical', () => assert.equal(SA.evaluatePortRisk(102, ''), 'critical'));
    it('OPC UA (4840) → critical', () => assert.equal(SA.evaluatePortRisk(4840, ''), 'critical'));
    it('DNP3 (20000) → critical', () => assert.equal(SA.evaluatePortRisk(20000, ''), 'critical'));
    it('SNMP (161) → high', () => assert.equal(SA.evaluatePortRisk(161, ''), 'high'));
    it('Elasticsearch (9200) → high', () => assert.equal(SA.evaluatePortRisk(9200, ''), 'high'));
    it('SSH (22) → medium', () => assert.equal(SA.evaluatePortRisk(22, ''), 'medium'));
    it('SMB (445) → medium', () => assert.equal(SA.evaluatePortRisk(445, ''), 'medium'));
    it('RDP (3389) → medium', () => assert.equal(SA.evaluatePortRisk(3389, ''), 'medium'));
    it('Port inconnu (9999) sans service → low', () => assert.equal(SA.evaluatePortRisk(9999, ''), 'low'));
});

describe('evaluatePortRisk — détection par nom de service', () => {
    it('service "modbus-tcp" sur port inconnu → critical', () =>
        assert.equal(SA.evaluatePortRisk(9999, 'modbus-tcp'), 'critical'));
    it('service "bacnet" → critical', () =>
        assert.equal(SA.evaluatePortRisk(9999, 'bacnet'), 'critical'));
    it('service "profinet" → critical', () =>
        assert.equal(SA.evaluatePortRisk(9999, 'profinet'), 'critical'));
    it('service "telnet" sur port non-standard → high', () =>
        assert.equal(SA.evaluatePortRisk(2323, 'telnet'), 'high'));
    it('service "vnc" → high', () =>
        assert.equal(SA.evaluatePortRisk(9999, 'vnc'), 'high'));
    it('service "snmp" → high', () =>
        assert.equal(SA.evaluatePortRisk(9999, 'snmp'), 'high'));
    it('service "http-alt" → medium', () =>
        assert.equal(SA.evaluatePortRisk(9999, 'http-alt'), 'medium'));
    it('service inconnu → low', () =>
        assert.equal(SA.evaluatePortRisk(9999, 'custom-service'), 'low'));
});

// --- analyzeVulnerabilities ---

describe('analyzeVulnerabilities — règle 1 : port critique', () => {
    it('aucun port → false', () =>
        assert.equal(SA.analyzeVulnerabilities([]), false));
    it('Telnet ouvert → true', () =>
        assert.equal(SA.analyzeVulnerabilities([{ port: 23, state: 'open', service: '' }]), true));
    it('Modbus ouvert → true', () =>
        assert.equal(SA.analyzeVulnerabilities([{ port: 502, state: 'open', service: '' }]), true));
    it('port critique fermé → false', () =>
        assert.equal(SA.analyzeVulnerabilities([{ port: 23, state: 'closed', service: '' }]), false));
});

describe('analyzeVulnerabilities — règle 2 : 2 ports high-risk', () => {
    it('SNMP + Elasticsearch → true', () =>
        assert.equal(SA.analyzeVulnerabilities([
            { port: 161, state: 'open', service: '' },
            { port: 9200, state: 'open', service: '' }
        ]), true));
    it('SNMP seul → false', () =>
        assert.equal(SA.analyzeVulnerabilities([
            { port: 161, state: 'open', service: '' }
        ]), false));
});

describe('analyzeVulnerabilities — règle 3 : 3 ports medium', () => {
    it('SSH + HTTP + RDP → true', () =>
        assert.equal(SA.analyzeVulnerabilities([
            { port: 22, state: 'open', service: '' },
            { port: 80, state: 'open', service: '' },
            { port: 3389, state: 'open', service: '' }
        ]), true));
    it('SSH + HTTP (2 medium) → false', () =>
        assert.equal(SA.analyzeVulnerabilities([
            { port: 22, state: 'open', service: '' },
            { port: 80, state: 'open', service: '' }
        ]), false));
});

describe('analyzeVulnerabilities — règle 4 : 8+ ports ouverts', () => {
    const safe = (n) => Array.from({ length: n }, (_, i) =>
        ({ port: 10000 + i, state: 'open', service: 'custom' }));
    it('8 ports non-critiques → true', () =>
        assert.equal(SA.analyzeVulnerabilities(safe(8)), true));
    it('7 ports non-critiques → false', () =>
        assert.equal(SA.analyzeVulnerabilities(safe(7)), false));
});

describe('analyzeVulnerabilities — règle 5 : 3 services non sécurisés', () => {
    it('FTP + Telnet + HTTP → true', () =>
        assert.equal(SA.analyzeVulnerabilities([
            { port: 21, state: 'open', service: '' },
            { port: 23, state: 'open', service: '' },
            { port: 80, state: 'open', service: '' }
        ]), true));
});

describe('analyzeVulnerabilities — règle 6 : service dangereux par nom', () => {
    it('service nommé "modbus" sur port non-standard → true', () =>
        assert.equal(SA.analyzeVulnerabilities([
            { port: 9999, state: 'open', service: 'modbus' }
        ]), true));
    it('service "vnc-display" → true', () =>
        assert.equal(SA.analyzeVulnerabilities([
            { port: 9999, state: 'open', service: 'vnc-display' }
        ]), true));
    it('service "custom-app" sans danger → false', () =>
        assert.equal(SA.analyzeVulnerabilities([
            { port: 9999, state: 'open', service: 'custom-app' }
        ]), false));
});

// --- analyzeCriticalServices ---

describe('analyzeCriticalServices', () => {
    it('Telnet ouvert → 1 service critique', () => {
        const result = SA.analyzeCriticalServices([{ port: 23, state: 'open', service: 'telnet' }]);
        assert.equal(result.length, 1);
        assert.equal(result[0].risk, 'critical');
    });
    it('utilise le nom de service nmap si fourni', () => {
        const result = SA.analyzeCriticalServices([{ port: 23, state: 'open', service: 'telnetd' }]);
        assert.equal(result[0].service, 'telnetd');
    });
    it('port connu mais fermé → ignoré', () => {
        const result = SA.analyzeCriticalServices([{ port: 23, state: 'closed', service: 'telnet' }]);
        assert.equal(result.length, 0);
    });
    it('RDP (3389) ouvert → détecté', () => {
        const result = SA.analyzeCriticalServices([{ port: 3389, state: 'open', service: 'ms-wbt-server' }]);
        assert.equal(result.length, 1);
        assert.equal(result[0].risk, 'medium');
    });
    it('plusieurs services critiques', () => {
        const ports = [
            { port: 23, state: 'open', service: 'telnet' },
            { port: 21, state: 'open', service: 'ftp' },
            { port: 22, state: 'open', service: 'ssh' }
        ];
        assert.equal(SA.analyzeCriticalServices(ports).length, 3);
    });
});

// ============================================================
// LOT PRIORITÉ 1 — nouvelles méthodes d'analyse enrichie
// ============================================================

// --- compareVersions / extractVersionNumber ---
describe('compareVersions', () => {
    it('1.0 < 2.0', () => assert.equal(SA.compareVersions('1.0', '2.0'), -1));
    it('2.4.41 > 2.4.0', () => assert.equal(SA.compareVersions('2.4.41', '2.4.0'), 1));
    it('7.0 == 7.0.0', () => assert.equal(SA.compareVersions('7.0', '7.0.0'), 0));
    it('6.9 < 7.0', () => assert.equal(SA.compareVersions('6.9', '7.0'), -1));
});

describe('extractVersionNumber', () => {
    it('extrait depuis chaîne libre', () =>
        assert.equal(SA.extractVersionNumber('Apache httpd 2.4.41 ((Ubuntu))'), '2.4.41'));
    it('null si absent', () =>
        assert.equal(SA.extractVersionNumber('nginx'), null));
});

// --- A2 analyzeNSEFindings ---
describe('analyzeNSEFindings', () => {
    it('détecte un host script VULNERABLE avec CVE → critical', () => {
        const host = {
            hostScripts: [{ id: 'smb-vuln-ms17-010', output: 'VULNERABLE:\nRemote Code Execution CVE-2017-0143' }],
            ports: []
        };
        const f = SA.analyzeNSEFindings(host);
        assert.equal(f.length, 1);
        assert.equal(f[0].severity, 'critical');
        assert.ok(f[0].cves.includes('CVE-2017-0143'));
        assert.equal(f[0].source, 'host');
    });
    it('ftp-anon sur un port → high', () => {
        const host = {
            hostScripts: [],
            ports: [{ port: 21, state: 'open', service: 'ftp', scripts: [{ id: 'ftp-anon', output: 'Anonymous FTP login allowed' }] }]
        };
        const f = SA.analyzeNSEFindings(host);
        assert.equal(f.length, 1);
        assert.equal(f[0].severity, 'high');
        assert.equal(f[0].source, 'port 21');
    });
    it('ssl faible (TLS 1.0) → medium', () => {
        const host = {
            hostScripts: [],
            ports: [{ port: 443, state: 'open', service: 'https', scripts: [{ id: 'ssl-enum-ciphers', output: 'TLSv1.0 supported, weak ciphers RC4' }] }]
        };
        const f = SA.analyzeNSEFindings(host);
        assert.equal(f[0].severity, 'medium');
    });
    it('script bénin ignoré', () => {
        const host = {
            hostScripts: [{ id: 'http-title', output: 'Welcome page' }],
            ports: []
        };
        assert.equal(SA.analyzeNSEFindings(host).length, 0);
    });
    it('ignore les ports fermés', () => {
        const host = {
            hostScripts: [],
            ports: [{ port: 21, state: 'closed', service: 'ftp', scripts: [{ id: 'ftp-anon', output: 'allowed' }] }]
        };
        assert.equal(SA.analyzeNSEFindings(host).length, 0);
    });
});

// --- A3 analyzeServiceVersions ---
describe('analyzeServiceVersions', () => {
    it('OpenSSH 6.6 → finding medium', () => {
        const host = { ports: [{ port: 22, state: 'open', service: 'ssh', version: 'OpenSSH 6.6.1p1' }] };
        const f = SA.analyzeServiceVersions(host);
        assert.equal(f.length, 1);
        assert.equal(f[0].name, 'OpenSSH');
        assert.equal(f[0].severity, 'medium');
    });
    it('OpenSSH 8.2 → aucun finding', () => {
        const host = { ports: [{ port: 22, state: 'open', service: 'ssh', version: 'OpenSSH 8.2p1' }] };
        assert.equal(SA.analyzeServiceVersions(host).length, 0);
    });
    it('vsftpd 2.3.4 → critical (backdoor)', () => {
        const host = { ports: [{ port: 21, state: 'open', service: 'ftp', version: 'vsftpd 2.3.4' }] };
        const f = SA.analyzeServiceVersions(host);
        assert.equal(f[0].severity, 'critical');
    });
    it('Apache 2.2 → finding ; Apache 2.4.41 → aucun', () => {
        const old = { ports: [{ port: 80, state: 'open', service: 'http', version: 'Apache httpd 2.2.15' }] };
        const cur = { ports: [{ port: 80, state: 'open', service: 'http', version: 'Apache httpd 2.4.41' }] };
        assert.equal(SA.analyzeServiceVersions(old).length, 1);
        assert.equal(SA.analyzeServiceVersions(cur).length, 0);
    });
    it('sans version → aucun finding', () => {
        const host = { ports: [{ port: 22, state: 'open', service: 'ssh', version: '' }] };
        assert.equal(SA.analyzeServiceVersions(host).length, 0);
    });
});

// --- A4 analyzeOSRisk ---
describe('analyzeOSRisk', () => {
    it('Windows XP → critical', () => {
        const r = SA.analyzeOSRisk({ os: { name: 'Microsoft Windows XP SP3', accuracy: '95' } });
        assert.equal(r.severity, 'critical');
    });
    it('Windows 7 → high', () => {
        const r = SA.analyzeOSRisk({ os: { name: 'Microsoft Windows 7 Professional', accuracy: '90' } });
        assert.equal(r.severity, 'high');
    });
    it('Windows Server 2003 → high', () => {
        const r = SA.analyzeOSRisk({ os: { name: 'Microsoft Windows Server 2003', accuracy: '92' } });
        assert.equal(r.severity, 'high');
    });
    it('Windows 10 récent → null', () => {
        assert.equal(SA.analyzeOSRisk({ os: { name: 'Microsoft Windows 10 21H2', accuracy: '88' } }), null);
    });
    it('os absent → null', () => {
        assert.equal(SA.analyzeOSRisk({}), null);
    });
});

// --- A1 calculateRiskScore ---
describe('calculateRiskScore', () => {
    it('host sans port ouvert → score 0, niveau info', () => {
        const r = SA.calculateRiskScore({ ports: [] });
        assert.equal(r.score, 0);
        assert.equal(r.level, 'info');
    });
    it('NSE critique → score élevé + niveau critique', () => {
        const host = {
            hostScripts: [{ id: 'smb-vuln-ms17-010', output: 'VULNERABLE: CVE-2017-0143' }],
            ports: [{ port: 445, state: 'open', service: 'microsoft-ds', scripts: [] }]
        };
        const r = SA.calculateRiskScore(host);
        assert.ok(r.score >= 40, `score attendu >=40, obtenu ${r.score}`);
        assert.equal(r.level, 'critical');
        assert.equal(r.nseFindings.length, 1);
    });
    it('score borné à 100', () => {
        const host = {
            hostScripts: [
                { id: 'smb-vuln-ms17-010', output: 'VULNERABLE CVE-2017-0143' },
                { id: 'smb-vuln-ms08-067', output: 'VULNERABLE CVE-2008-4250' }
            ],
            os: { name: 'Windows XP', accuracy: '95' },
            ports: [
                { port: 23, state: 'open', service: 'telnet', version: '', scripts: [] },
                { port: 21, state: 'open', service: 'ftp', version: 'vsftpd 2.3.4', scripts: [] },
                { port: 502, state: 'open', service: 'modbus', version: '', scripts: [] }
            ]
        };
        const r = SA.calculateRiskScore(host);
        assert.ok(r.score <= 100);
        assert.equal(r.level, 'critical');
    });
    it('un seul port medium → niveau low ou medium', () => {
        const host = { ports: [{ port: 22, state: 'open', service: 'ssh', version: '', scripts: [] }] };
        const r = SA.calculateRiskScore(host);
        assert.ok(['low', 'medium'].includes(r.level));
    });
});

// --- labels / couleurs ---
describe('getScoreLabel / getScoreColor', () => {
    it('label critique', () => assert.equal(SA.getScoreLabel('critical'), 'CRITIQUE'));
    it('label info', () => assert.equal(SA.getScoreLabel('info'), 'OK'));
    it('couleur définie pour chaque niveau', () => {
        ['critical', 'high', 'medium', 'low', 'info'].forEach(l => {
            assert.match(SA.getScoreColor(l), /^#[0-9a-f]{6}$/i);
        });
    });
});

