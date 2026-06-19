import { describe, it, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadModule } from './helpers/load-module.js';
import { MockDOMParser } from './helpers/mock-dom-parser.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

let FP;
let captured = [];

before(() => {
    // Charger SecurityAnalyzer sans dépendances
    const SA = loadModule(
        join(__dirname, '../assets/js/security-analyzer.js'),
        'SecurityAnalyzer'
    );

    // Charger FileProcessor en injectant les globaux requis
    FP = loadModule(
        join(__dirname, '../assets/js/file-processor.js'),
        'FileProcessor',
        {
            SecurityAnalyzer: SA,
            DOMParser: MockDOMParser,
            addHostToData: (host) => captured.push(host),
        }
    );
});

beforeEach(() => { captured = []; });

// --- parseNmapText ---

describe('parseNmapText — hôte simple', () => {
    it('extrait IP, VLAN et ports', () => {
        FP.parseNmapText(`
Nmap scan report for 192.168.1.1
22/tcp  open  ssh
80/tcp  open  http
`, 'VLAN10');
        assert.equal(captured.length, 1);
        assert.equal(captured[0].ip, '192.168.1.1');
        assert.equal(captured[0].vlan, 'VLAN10');
        assert.equal(captured[0].ports.length, 2);
    });

    it('port open est bien parsé', () => {
        FP.parseNmapText('Nmap scan report for 10.0.0.1\n22/tcp open ssh\n', 'V1');
        assert.equal(captured[0].ports[0].state, 'open');
        assert.equal(captured[0].ports[0].port, 22);
        assert.equal(captured[0].ports[0].service, 'ssh');
    });

    it('port filtered est bien parsé', () => {
        FP.parseNmapText('Nmap scan report for 10.0.0.1\n8080/tcp filtered http-proxy\n', 'V1');
        assert.equal(captured[0].ports[0].state, 'filtered');
    });
});

describe('parseNmapText — hostname', () => {
    it('extrait hostname PTR depuis "report for hostname (IP)"', () => {
        FP.parseNmapText('Nmap scan report for srv-dc01.corp.local (10.0.0.1)\n22/tcp open ssh\n', 'V1');
        assert.equal(captured[0].ip, '10.0.0.1');
        assert.equal(captured[0].hostnames.length, 1);
        assert.equal(captured[0].hostnames[0].name, 'srv-dc01.corp.local');
        assert.equal(captured[0].hostnames[0].type, 'PTR');
    });

    it('hôte sans hostname → hostnames tableau vide', () => {
        FP.parseNmapText('Nmap scan report for 10.0.0.2\n22/tcp open ssh\n', 'V1');
        assert.equal(captured[0].hostnames.length, 0);
    });
});

describe('parseNmapText — NSE scripts', () => {
    it('script single-line |_scriptname: value', () => {
        FP.parseNmapText(
            'Nmap scan report for 10.0.0.1\n80/tcp open http\n|_http-title: My Page\n',
            'V1'
        );
        const scripts = captured[0].ports[0].scripts;
        assert.equal(scripts.length, 1);
        assert.equal(scripts[0].id, 'http-title');
        assert.equal(scripts[0].output, 'My Page');
    });

    it('script multi-lignes | scriptname: + continuations', () => {
        FP.parseNmapText(
            'Nmap scan report for 10.0.0.1\n22/tcp open ssh\n| ssh-hostkey:\n|   2048 aa:bb:cc (RSA)\n|_  256 dd:ee:ff (ECDSA)\n',
            'V1'
        );
        const scripts = captured[0].ports[0].scripts;
        assert.equal(scripts.length, 1);
        assert.equal(scripts[0].id, 'ssh-hostkey');
        assert.ok(scripts[0].output.includes('RSA'));
        assert.ok(scripts[0].output.includes('ECDSA'));
    });

    it('ftp-anon script détecté', () => {
        FP.parseNmapText(
            'Nmap scan report for 10.0.0.1\n21/tcp open ftp\n|_ftp-anon: Anonymous FTP login allowed\n',
            'V1'
        );
        assert.equal(captured[0].ports[0].scripts[0].id, 'ftp-anon');
        assert.ok(captured[0].ports[0].scripts[0].output.includes('Anonymous'));
    });

    it('plusieurs scripts sur un même port', () => {
        FP.parseNmapText(
            'Nmap scan report for 10.0.0.1\n80/tcp open http\n|_http-title: Test\n|_http-server-header: nginx\n',
            'V1'
        );
        assert.equal(captured[0].ports[0].scripts.length, 2);
    });

    it('script ignoré si pas de port courant', () => {
        FP.parseNmapText(
            'Nmap scan report for 10.0.0.1\n|_http-title: Orphan\n22/tcp open ssh\n',
            'V1'
        );
        assert.equal(captured[0].ports[0].scripts.length, 0);
    });
});

describe('parseNmapText — MAC et vendor', () => {
    it('extrait adresse MAC et vendor', () => {
        FP.parseNmapText(`
Nmap scan report for 10.0.0.1
80/tcp open http
MAC Address: AA:BB:CC:DD:EE:FF (Siemens AG)
`, 'V1');
        assert.equal(captured[0].macAddress, 'AA:BB:CC:DD:EE:FF');
        assert.equal(captured[0].vendor, 'Siemens AG');
    });

    it('hôte sans MAC → macAddress null', () => {
        FP.parseNmapText('Nmap scan report for 10.0.0.2\n22/tcp open ssh\n', 'V1');
        assert.equal(captured[0].macAddress, null);
        assert.equal(captured[0].vendor, null);
    });
});

describe('parseNmapText — cas limites', () => {
    it('hôte sans ports ouverts → non ajouté', () => {
        FP.parseNmapText('Nmap scan report for 10.0.0.99\n', 'V1');
        assert.equal(captured.length, 0);
    });

    it('plusieurs hôtes dans un même fichier', () => {
        FP.parseNmapText(`
Nmap scan report for 10.0.0.1
22/tcp open ssh

Nmap scan report for 10.0.0.2
80/tcp open http
`, 'VLAN20');
        assert.equal(captured.length, 2);
        assert.equal(captured[0].ip, '10.0.0.1');
        assert.equal(captured[1].ip, '10.0.0.2');
    });

    it('analyse de vulnérabilité appliquée (Telnet → vulnerable)', () => {
        FP.parseNmapText('Nmap scan report for 10.0.0.1\n23/tcp open telnet\n', 'V1');
        assert.equal(captured[0].vulnerable, true);
    });

    it('hôte sûr → non vulnérable', () => {
        FP.parseNmapText('Nmap scan report for 10.0.0.1\n443/tcp open https\n', 'V1');
        assert.equal(captured[0].vulnerable, false);
    });
});

// --- parseNmapXML ---

describe('parseNmapXML — hôte simple', () => {
    it('extrait IP, VLAN et ports', () => {
        FP.parseNmapXML(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <ports>
      <port portid="22" protocol="tcp">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>`, 'VLAN10');
        assert.equal(captured.length, 1);
        assert.equal(captured[0].ip, '192.168.1.100');
        assert.equal(captured[0].vlan, 'VLAN10');
        assert.equal(captured[0].ports[0].port, 22);
        assert.equal(captured[0].ports[0].service, 'ssh');
        assert.equal(captured[0].ports[0].state, 'open');
    });

    it('extrait vendor et MAC depuis le XML', () => {
        FP.parseNmapXML(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Cisco Systems"/>
    <ports>
      <port portid="80" protocol="tcp">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>`, 'VLAN20');
        assert.equal(captured[0].vendor, 'Cisco Systems');
        assert.equal(captured[0].macAddress, 'AA:BB:CC:DD:EE:FF');
    });

    it('plusieurs ports dans un hôte', () => {
        FP.parseNmapXML(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port portid="22" protocol="tcp"><state state="open"/><service name="ssh"/></port>
      <port portid="80" protocol="tcp"><state state="open"/><service name="http"/></port>
      <port portid="443" protocol="tcp"><state state="open"/><service name="https"/></port>
    </ports>
  </host>
</nmaprun>`, 'V1');
        assert.equal(captured[0].ports.length, 3);
    });
});

describe('parseNmapXML — cas limites', () => {
    it('hôte sans adresse IPv4 → ignoré', () => {
        FP.parseNmapXML(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
  </host>
</nmaprun>`, 'V1');
        assert.equal(captured.length, 0);
    });

    it('plusieurs hôtes', () => {
        FP.parseNmapXML(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports><port portid="22" protocol="tcp"><state state="open"/><service name="ssh"/></port></ports>
  </host>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports><port portid="80" protocol="tcp"><state state="open"/><service name="http"/></port></ports>
  </host>
</nmaprun>`, 'V1');
        assert.equal(captured.length, 2);
    });

    it('port Modbus → hôte vulnérable', () => {
        FP.parseNmapXML(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port portid="502" protocol="tcp">
        <state state="open"/>
        <service name="modbus"/>
      </port>
    </ports>
  </host>
</nmaprun>`, 'ICS');
        assert.equal(captured[0].vulnerable, true);
    });
});
