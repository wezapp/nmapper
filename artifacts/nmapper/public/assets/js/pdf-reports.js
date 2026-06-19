// pdf-reports.js - Module de génération de rapports PDF
const PDFReports = {
    
    addPDFReportSection() {
        // Section already present in HTML with data-action attributes — nothing to inject
    },

    togglePDFSection() {
        const content = document.getElementById('pdfContent');
        content.classList.toggle('active');
    },

    updateHostSelector() {
        const select = document.getElementById('hostSelect');
        if (!select) return;
        
        select.innerHTML = '<option value="">-- Choisir un hôte --</option>';
        
        // Trier les hôtes par IP
        const sortedHosts = [...networkData.hosts].sort((a, b) => {
            const aOctets = a.ip.split('.').map(Number);
            const bOctets = b.ip.split('.').map(Number);
            
            for (let i = 0; i < 4; i++) {
                if (aOctets[i] !== bOctets[i]) {
                    return aOctets[i] - bOctets[i];
                }
            }
            return 0;
        });
        
        // Grouper par VLAN
        const hostsByVlan = {};
        sortedHosts.forEach(host => {
            if (!hostsByVlan[host.vlan]) {
                hostsByVlan[host.vlan] = [];
            }
            hostsByVlan[host.vlan].push(host);
        });
        
        Object.keys(hostsByVlan).sort().forEach(vlan => {
            const optgroup = document.createElement('optgroup');
            optgroup.label = `VLAN ${vlan}`;
            
            hostsByVlan[vlan].forEach(host => {
                const option = document.createElement('option');
                option.value = host.ip;
                
                let label = `${host.ip}`;
                if (host.vendor) {
                    label += ` (${host.vendor})`;
                }
                if (host.vulnerable) {
                    label += ` ⚠️`;
                }
                
                const openPorts = host.ports.filter(p => p.state === 'open').length;
                label += ` - ${openPorts} port(s)`;
                
                option.textContent = label;
                optgroup.appendChild(option);
            });
            
            select.appendChild(optgroup);
        });
    },

    // Générer un rapport pour un VLAN spécifique
    async generateVLANReport(vlanId) {
        const data = filteredData || networkData;
        const vlan = data.vlans[vlanId];
        
        if (!vlan || vlan.hosts.length === 0) {
            showMessage('warning', '⚠️ Aucun hôte trouvé dans ce VLAN');
            return;
        }

        if (typeof window.jspdf === 'undefined') {
            showMessage('error', '❌ Bibliothèque PDF non chargée. Veuillez réessayer dans quelques secondes.');
            return;
        }

        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            
            const primaryColor = [41, 128, 185];
            const dangerColor = [231, 76, 60];
            const successColor = [46, 204, 113];
            
            let yPosition = 20;
            const pageHeight = doc.internal.pageSize.height;
            const margin = 20;
            
            const checkPageBreak = (requiredSpace = 20) => {
                if (yPosition + requiredSpace > pageHeight - margin) {
                    doc.addPage();
                    yPosition = 20;
                    return true;
                }
                return false;
            };
            
            // En-tête
            doc.setFontSize(20);
            doc.setTextColor(...primaryColor);
            doc.text(`RAPPORT DE SÉCURITÉ - VLAN ${vlanId}`, margin, yPosition);
            yPosition += 15;
            
            const now = new Date();
            doc.setFontSize(10);
            doc.setTextColor(100, 100, 100);
            doc.text(`Généré le: ${now.toLocaleDateString('fr-FR')} à ${now.toLocaleTimeString('fr-FR')}`, margin, yPosition);
            yPosition += 20;
            
            // Statistiques du VLAN
            doc.setFontSize(16);
            doc.setTextColor(...primaryColor);
            doc.text('STATISTIQUES DU VLAN', margin, yPosition);
            yPosition += 12;
            
            const vulnerableHosts = vlan.hosts.filter(h => h.vulnerable);
            const totalOpenPorts = vlan.hosts.reduce((sum, h) => sum + h.ports.filter(p => p.state === 'open').length, 0);
            
            const stats = [
                ` VLAN ID: ${vlanId}`,
                ` Nombre d'hôtes: ${vlan.hosts.length}`,
                ` Hôtes vulnérables: ${vulnerableHosts.length}`,
                ` Ports ouverts total: ${totalOpenPorts}`,
                ` Taux de vulnérabilité: ${Math.round((vulnerableHosts.length / vlan.hosts.length) * 100)}%`
            ];
            
            doc.setFontSize(11);
            doc.setTextColor(0, 0, 0);
            stats.forEach(stat => {
                checkPageBreak();
                doc.text(stat, margin + 5, yPosition);
                yPosition += 8;
            });
            
            yPosition += 15;
            
            // Liste des hôtes vulnérables
            if (vulnerableHosts.length > 0) {
                checkPageBreak(30);
                doc.setFontSize(16);
                doc.setTextColor(...dangerColor);
                doc.text('! HÔTES SENSIBLES', margin, yPosition);
                yPosition += 12;
                
                doc.setFontSize(10);
                vulnerableHosts.forEach((host, index) => {
                    checkPageBreak();
                    doc.setTextColor(...dangerColor);
                    doc.text(`${index + 1}. ${host.ip}`, margin + 5, yPosition);
                    doc.setTextColor(0, 0, 0);
                    const openPorts = host.ports.filter(p => p.state === 'open').length;
                    doc.text(`(${openPorts} ports ouverts)`, margin + 50, yPosition);
                    if (host.vendor) {
                        doc.text(`- ${host.vendor}`, margin + 100, yPosition);
                    }
                    yPosition += 7;
                });
                
                yPosition += 15;
            }
            
            // Liste de tous les hôtes
            checkPageBreak(30);
            doc.setFontSize(16);
            doc.setTextColor(...primaryColor);
            doc.text('INVENTAIRE DES HÔTES', margin, yPosition);
            yPosition += 12;
            
            doc.setFontSize(9);
            doc.setTextColor(0, 0, 0);
            
            // En-tête du tableau
            doc.text('IP', margin + 5, yPosition);
            doc.text('Vendor', margin + 45, yPosition);
            doc.text('Ports', margin + 100, yPosition);
            doc.text('Statut', margin + 130, yPosition);
            yPosition += 8;
            
            doc.setDrawColor(200, 200, 200);
            doc.line(margin, yPosition - 2, 190, yPosition - 2);
            
            vlan.hosts.forEach(host => {
                checkPageBreak();
                
                doc.setTextColor(0, 0, 0);
                doc.text(host.ip, margin + 5, yPosition);
                doc.text(host.vendor || 'Inconnu', margin + 45, yPosition);
                doc.text(host.ports.filter(p => p.state === 'open').length.toString(), margin + 100, yPosition);
                
                if (host.vulnerable) {
                    doc.setTextColor(...dangerColor);
                    doc.text('SENSIBLE', margin + 130, yPosition);
                } else {
                    doc.setTextColor(...successColor);
                    doc.text('SÉCURISÉ', margin + 130, yPosition);
                }
                
                yPosition += 7;
            });
            
            // Pied de page
            const totalPages = doc.getNumberOfPages();
            for (let i = 1; i <= totalPages; i++) {
                doc.setPage(i);
                doc.setFontSize(8);
                doc.setTextColor(150, 150, 150);
                doc.text(`Page ${i}/${totalPages}`, 180, pageHeight - 10);
                doc.text(`Rapport VLAN ${vlanId} - NMapper`, margin, pageHeight - 10);
            }
            
            const fileName = `rapport_vlan_${vlanId}_${now.toISOString().slice(0, 10)}.pdf`;
            await EncryptExport.downloadEncrypted(doc.output('blob'), fileName);
            showMessage('success', `✅ Rapport VLAN chiffré généré: ${fileName}`);
            if (typeof ActivityLog !== 'undefined') ActivityLog.logEvent('export_pdf', fileName, 'success', `VLAN ${vlanId}`);
            
        } catch (error) {
            console.error('Erreur lors de la génération du rapport VLAN:', error);
            showMessage('error', '❌ Erreur lors de la génération du rapport VLAN');
        }
    },

    async generateHostReport(hostIP) {
        const host = networkData.hosts.find(h => h.ip === hostIP);
        if (!host) {
            showMessage('error', '❌ Hôte non trouvé');
            return;
        }

        if (typeof window.jspdf === 'undefined') {
            showMessage('error', '❌ Bibliothèque PDF non chargée. Veuillez réessayer dans quelques secondes.');
            return;
        }

        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            
            const primaryColor = [41, 128, 185];
            const dangerColor = [231, 76, 60];
            const successColor = [46, 204, 113];
            const warningColor = [241, 196, 15];
            
            let yPosition = 20;
            const pageHeight = doc.internal.pageSize.height;
            const margin = 20;
            
            const checkPageBreak = (requiredSpace = 20) => {
                if (yPosition + requiredSpace > pageHeight - margin) {
                    doc.addPage();
                    yPosition = 20;
                    return true;
                }
                return false;
            };
            
            // En-tête
            doc.setFontSize(20);
            doc.setTextColor(...primaryColor);
            doc.text('RAPPORT DE SÉCURITÉ RÉSEAU', margin, yPosition);
            yPosition += 8;
            
            doc.setFontSize(14);
            doc.setTextColor(0, 0, 0);
            doc.text(`Analyse de l'hôte: ${host.ip}`, margin, yPosition);
            yPosition += 5;
            
            const now = new Date();
            doc.setFontSize(10);
            doc.setTextColor(100, 100, 100);
            doc.text(`Généré le: ${now.toLocaleDateString('fr-FR')} à ${now.toLocaleTimeString('fr-FR')}`, margin, yPosition);
            yPosition += 3;
            
            // Ligne de séparation
            doc.setDrawColor(...primaryColor);
            doc.line(margin, yPosition, 190, yPosition);
            yPosition += 10;
            
            // Informations générales
            checkPageBreak(30);
            doc.setFontSize(16);
            doc.setTextColor(...primaryColor);
            doc.text('INFORMATIONS GÉNÉRALES', margin, yPosition);
            yPosition += 5;
            
            doc.setFontSize(11);
            doc.setTextColor(0, 0, 0);
            
            const generalInfo = [
                `- Adresse IP: ${host.ip}`,
                `- VLAN: ${host.vlan}`,
                `- Fabricant: ${host.vendor || 'Non identifié'}`,
                `- Adresse MAC: ${host.macAddress || 'Non disponible'}`,
                `- Statut de sécurité: ${host.vulnerable ? 'HÔTE À RISQUE' : 'Sécurisé'}`
            ];
            
            generalInfo.forEach(info => {
                checkPageBreak();
                if (info.includes('HÔTE À RISQUE')) {
                    doc.setTextColor(...dangerColor);
                } else {
                    doc.setTextColor(0, 0, 0);
                }
                doc.text(info, margin + 5, yPosition);
                yPosition += 5;
            });
            
            yPosition += 8;
            
            // Analyse des ports
            checkPageBreak(30);
            doc.setFontSize(16);
            doc.setTextColor(...primaryColor);
            doc.text('ANALYSE DES PORTS', margin, yPosition);
            yPosition += 5;
            
            const openPorts = host.ports.filter(p => p.state === 'open');
            const closedPorts = host.ports.filter(p => p.state === 'closed');
            const filteredPorts = host.ports.filter(p => p.state === 'filtered');
            
            doc.setFontSize(11);
            doc.setTextColor(0, 0, 0);
            doc.text(`- Statistiques:`, margin + 5, yPosition);
            yPosition += 5;
            
            doc.setTextColor(...successColor);
            doc.text(`   • Ports ouverts: ${openPorts.length}`, margin + 10, yPosition);
            yPosition += 4;
            
            doc.setTextColor(...dangerColor);
            doc.text(`   • Ports fermés: ${closedPorts.length}`, margin + 10, yPosition);
            yPosition += 4;
            
            doc.setTextColor(...warningColor);
            doc.text(`   • Ports filtrés: ${filteredPorts.length}`, margin + 10, yPosition);
            yPosition += 8;
            
            // Détail des ports ouverts
            if (openPorts.length > 0) {
                yPosition = this.addPortsDetails(doc, openPorts, yPosition, margin, checkPageBreak, dangerColor, warningColor, successColor);
            }
            
            // Recommandations
            yPosition = this.addRecommendations(doc, host, yPosition, margin, checkPageBreak, primaryColor, dangerColor);
            
            // Pied de page
            this.addFooter(doc, host, pageHeight, margin);
            
            const fileName = `rapport_securite_${host.ip.replace(/\./g, '_')}_${now.toISOString().slice(0, 10)}.pdf`;
            await EncryptExport.downloadEncrypted(doc.output('blob'), fileName);
            showMessage('success', `✅ Rapport PDF chiffré généré: ${fileName}`);
            if (typeof ActivityLog !== 'undefined') ActivityLog.logEvent('export_pdf', fileName, 'success', `hôte ${hostIP}`);
            
        } catch (error) {
            console.error('Erreur lors de la génération du PDF:', error);
            showMessage('error', '❌ Erreur lors de la génération du rapport PDF');
        }
    },

    addPortsDetails(doc, openPorts, yPosition, margin, checkPageBreak, dangerColor, warningColor, successColor) {
        checkPageBreak(20);
        doc.setTextColor(...dangerColor);
        doc.setFontSize(12);
        doc.text('PORTS OUVERTS', margin + 5, yPosition);
        yPosition += 5;
        
        doc.setFontSize(9);
        doc.setTextColor(0, 0, 0);
        
        doc.text('Port', margin + 10, yPosition);
        doc.text('État', margin + 40, yPosition);
        doc.text('Service', margin + 70, yPosition);
        doc.text('Risque', margin + 120, yPosition);
        yPosition += 5;
        
        doc.setDrawColor(200, 200, 200);
        doc.line(margin + 5, yPosition - 2, 180, yPosition - 2);
        
        openPorts.forEach(port => {
            checkPageBreak();
            
            const riskLevel = SecurityAnalyzer.evaluatePortRisk(port.port, port.service);
            let riskColor, riskText;
            
            switch(riskLevel) {
                case 'critical':
                    riskColor = dangerColor;
                    riskText = 'CRITIQUE !';
                    break;
                case 'high':
                    riskColor = dangerColor;
                    riskText = 'RISQUÉ';
                    break;
                case 'medium':
                    riskColor = warningColor;
                    riskText = 'MOYEN';
                    break;
                default:
                    riskColor = successColor;
                    riskText = 'INCONNU';
            }
            
            doc.setTextColor(0, 0, 0);
            doc.text(port.port.toString(), margin + 10, yPosition);
            doc.text(port.state.toUpperCase(), margin + 40, yPosition);
            doc.text(port.service || 'unknown', margin + 70, yPosition);
            
            doc.setTextColor(...riskColor);
            doc.text(riskText, margin + 120, yPosition);
            
            yPosition += 3.5;
        });
        
        return yPosition + 8;
    },

    addRecommendations(doc, host, yPosition, margin, checkPageBreak, primaryColor, dangerColor) {
        checkPageBreak(30);
        doc.setFontSize(16);
        doc.setTextColor(...primaryColor);
        doc.text('RECOMMANDATIONS DE SÉCURITÉ', margin, yPosition);
        yPosition += 5;
        
        const recommendations = SecurityAnalyzer.generateSecurityRecommendations(host);
        
        doc.setFontSize(10);
        recommendations.forEach((recommendation, index) => {
            checkPageBreak(15);
            
            doc.setTextColor(...dangerColor);
            doc.text(`${index + 1}.`, margin + 5, yPosition);
            
            doc.setTextColor(0, 0, 0);
            const lines = doc.splitTextToSize(recommendation, 160);
            lines.forEach(line => {
                doc.text(line, margin + 15, yPosition);
                yPosition += 4;
            });
            yPosition += 3;
        });
        
        return yPosition;
    },

    addFooter(doc, host, pageHeight, margin) {
        const totalPages = doc.getNumberOfPages();
        for (let i = 1; i <= totalPages; i++) {
            doc.setPage(i);
            doc.setFontSize(8);
            doc.setTextColor(150, 150, 150);
            doc.text(`Page ${i}/${totalPages}`, 180, pageHeight - 10);
            doc.text(`Rapport généré par NMapper - ${host.ip}`, margin, pageHeight - 10);
        }
    },

    async generateGlobalReport() {
        if (networkData.hosts.length === 0) {
            showMessage('warning', 'Aucune donnée disponible pour générer un rapport');
            return;
        }

        if (typeof window.jspdf === 'undefined') {
            showMessage('error', 'Bibliothèque PDF non chargée. Veuillez réessayer dans quelques secondes.');
            return;
        }

        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            
            const primaryColor = [41, 128, 185];
            const dangerColor = [231, 76, 60];
            
            let yPosition = 20;
            const pageHeight = doc.internal.pageSize.height;
            const margin = 20;
            
            const checkPageBreak = (requiredSpace = 20) => {
                if (yPosition + requiredSpace > pageHeight - margin) {
                    doc.addPage();
                    yPosition = 20;
                    return true;
                }
                return false;
            };
            
            // En-tête
            doc.setFontSize(22);
            doc.setTextColor(...primaryColor);
            doc.text('RAPPORT DE SÉCURITÉ RÉSEAU GLOBAL', margin, yPosition);
            yPosition += 15;
            
            const now = new Date();
            doc.setFontSize(10);
            doc.setTextColor(100, 100, 100);
            doc.text(`Généré le: ${now.toLocaleDateString('fr-FR')} à ${now.toLocaleTimeString('fr-FR')}`, margin, yPosition);
            yPosition += 20;
            
            // Statistiques globales
            doc.setFontSize(16);
            doc.setTextColor(...primaryColor);
            doc.text('STATISTIQUES GLOBALES', margin, yPosition);
            yPosition += 12;
            
            const stats = [
                `Nombre total d'hôtes: ${networkData.hosts.length}`,
                `Nombre de VLANs: ${Object.keys(networkData.vlans).length}`,
                `Hôtes vulnérables: ${networkData.hosts.filter(h => h.vulnerable).length}`,
                `Ports ouverts total: ${networkData.hosts.reduce((sum, h) => sum + h.ports.filter(p => p.state === 'open').length, 0)}`,
                `Fichiers traités: ${networkData.stats.files}`
            ];
            
            doc.setFontSize(11);
            doc.setTextColor(0, 0, 0);
            stats.forEach(stat => {
                checkPageBreak();
                doc.text(stat, margin + 5, yPosition);
                yPosition += 8;
            });
            
            yPosition += 15;
            
            // Hôtes vulnérables
            const vulnerableHosts = networkData.hosts.filter(h => h.vulnerable);
            if (vulnerableHosts.length > 0) {
                checkPageBreak(30);
                doc.setFontSize(16);
                doc.setTextColor(...dangerColor);
                doc.text('HÔTES À RISQUE ÉLEVÉ', margin, yPosition);
                yPosition += 12;
                
                doc.setFontSize(10);
                vulnerableHosts.slice(0, 10).forEach((host, index) => {
                    checkPageBreak();
                    doc.setTextColor(...dangerColor);
                    doc.text(`${index + 1}. ${host.ip}`, margin + 5, yPosition);
                    doc.setTextColor(0, 0, 0);
                    doc.text(`(${host.ports.filter(p => p.state === 'open').length} ports ouverts)`, margin + 50, yPosition);
                    yPosition += 7;
                });
                
                yPosition += 15;
            }
            
            // Résumé par VLAN
            checkPageBreak(30);
            doc.setFontSize(16);
            doc.setTextColor(...primaryColor);
            doc.text('RÉSUMÉ PAR VLAN', margin, yPosition);
            yPosition += 12;
            
            Object.values(networkData.vlans).forEach(vlan => {
                checkPageBreak(15);
                const vulnerableCount = vlan.hosts.filter(h => h.vulnerable).length;
                
                doc.setFontSize(11);
                doc.setTextColor(0, 0, 0);
                doc.text(`VLAN ${vlan.id}:`, margin + 5, yPosition);
                doc.text(`${vlan.hosts.length} hôtes`, margin + 60, yPosition);
                
                if (vulnerableCount > 0) {
                    doc.setTextColor(...dangerColor);
                    doc.text(`(${vulnerableCount} vulnérables)`, margin + 100, yPosition);
                }
                
                yPosition += 8;
            });
            
            const fileName = `rapport_securite_global_${now.toISOString().slice(0, 10)}.pdf`;
            await EncryptExport.downloadEncrypted(doc.output('blob'), fileName);
            showMessage('success', `✅ Rapport global chiffré généré: ${fileName}`);
            if (typeof ActivityLog !== 'undefined') ActivityLog.logEvent('export_pdf', fileName, 'success', 'rapport global');
            
        } catch (error) {
            console.error('Erreur lors de la génération du rapport global:', error);
            showMessage('error', 'Erreur lors de la génération du rapport global');
        }
    },

    generateSelectedHostReport() {
        const selectedIP = document.getElementById('hostSelect').value;
        
        if (!selectedIP) {
            showMessage('warning', 'Veuillez sélectionner un hôte');
            return;
        }
        
        this.generateHostReport(selectedIP);
    },

    generateFilteredReport() {
        if (!filteredData || filteredData.hosts.length === 0) {
            showMessage('warning', 'Aucun résultat filtré disponible');
            return;
        }
        
        // Utiliser la même logique que le rapport global mais avec les données filtrées
        const originalData = networkData;
        networkData = filteredData; // Temporairement remplacer
        
        this.generateGlobalReport();
        
        networkData = originalData; // Restaurer
    }
};

// Wrappers globaux requis par le dispatcher data-action de main.js
function togglePDFSection()          { PDFReports.togglePDFSection(); }
function generateGlobalReport()      { PDFReports.generateGlobalReport().catch(e => showMessage('error', '❌ ' + e.message)); }
function generateSelectedHostReport(){ PDFReports.generateSelectedHostReport().catch(e => showMessage('error', '❌ ' + e.message)); }
function generateFilteredReport()    { PDFReports.generateFilteredReport().catch(e => showMessage('error', '❌ ' + e.message)); }