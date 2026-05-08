// Global variables
let uploadedFile = null;
let xmlContent = null;
let parsedConfig = null;
let siteName = '';
let currentPage = 1;
let totalPages = 1;
const itemsPerPage = 3; // Number of sections per page

// DOM Elements
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const uploadSection = document.getElementById('uploadSection');
const siteNameSection = document.getElementById('siteNameSection');
const reportSection = document.getElementById('reportSection');

// Event Listeners
dropZone.addEventListener('dragover', handleDragOver);
dropZone.addEventListener('dragleave', handleDragLeave);
dropZone.addEventListener('drop', handleDrop);
fileInput.addEventListener('change', handleFileSelect);

function handleDragOver(e) {
    e.preventDefault();
    dropZone.classList.add('drag-over');
}

function handleDragLeave(e) {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
}

function handleDrop(e) {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        processFile(files[0]);
    }
}

function handleFileSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
        processFile(files[0]);
    }
}

function processFile(file) {
    if (!file.name.endsWith('.xml')) {
        alert('Please upload an XML file');
        return;
    }
    
    uploadedFile = file;
    const reader = new FileReader();
    
    reader.onload = function(e) {
        xmlContent = e.target.result;
        showSiteNameModal();
    };
    
    reader.onerror = function() {
        alert('Error reading file');
    };
    
    reader.readAsText(file);
}

function showSiteNameModal() {
    uploadSection.style.display = 'none';
    siteNameSection.style.display = 'block';
}

function cancelUpload() {
    siteNameSection.style.display = 'none';
    uploadSection.style.display = 'flex';
    uploadedFile = null;
    xmlContent = null;
    fileInput.value = '';
}

function generateReport() {
    siteName = document.getElementById('siteName').value.trim();
    
    if (!siteName) {
        alert('Please enter a site name');
        return;
    }
    
    try {
        parsedConfig = parseXML(xmlContent);
        displayReport();
        siteNameSection.style.display = 'none';
        reportSection.style.display = 'block';
    } catch (error) {
        alert('Error parsing configuration: ' + error.message);
        console.error(error);
    }
}

function parseXML(xmlString) {
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(xmlString, 'text/xml');
    
    // Check for parsing errors
    const parserError = xmlDoc.querySelector('parsererror');
    if (parserError) {
        throw new Error('Invalid XML format');
    }
    
    const config = {
        system: {},
        interfaces: [],
        firewall: {
            rules: [],
            nat: []
        },
        ipsec: {
            tunnels: [],
            psk: []
        },
        dhcp: [],
        gateways: [],
        vlans: [],
        services: {},
        dns: {},
        ntp: {}
    };
    
    // Parse System Information
    const system = xmlDoc.querySelector('system');
    if (system) {
        config.system = {
            hostname: getElementText(system, 'hostname'),
            domain: getElementText(system, 'domain'),
            timezone: getElementText(system, 'timezone'),
            dnsServers: [],
            webgui: {
                protocol: getElementText(system.querySelector('webgui'), 'protocol'),
                port: getElementText(system.querySelector('webgui'), 'port')
            }
        };
        
        // DNS Servers
        const dnsServers = system.querySelectorAll('dnsserver');
        dnsServers.forEach(dns => {
            config.system.dnsServers.push(dns.textContent);
        });
    }
    
    // Parse Interfaces
    const interfaces = xmlDoc.querySelectorAll('interfaces > *');
    interfaces.forEach(iface => {
        const tag = iface.tagName;
        if (tag !== 'lo0' && tag !== 'enc0') {
            config.interfaces.push({
                name: tag,
                descr: getElementText(iface, 'descr') || tag,
                if: getElementText(iface, 'if'),
                ipaddr: getElementText(iface, 'ipaddr'),
                subnet: getElementText(iface, 'subnet'),
                enable: getElementText(iface, 'enable') === '1'
            });
        }
    });
    
    // Parse VLANs
    const vlans = xmlDoc.querySelectorAll('vlans > vlan');
    vlans.forEach(vlan => {
        config.vlans.push({
            tag: getElementText(vlan, 'tag'),
            descr: getElementText(vlan, 'descr'),
            if: getElementText(vlan, 'if'),
            vlanif: getElementText(vlan, 'vlanif')
        });
    });
    
    // Parse Firewall Rules
    const rules = xmlDoc.querySelectorAll('filter > rule');
    rules.forEach(rule => {
        config.firewall.rules.push({
            type: getElementText(rule, 'type'),
            interface: getElementText(rule, 'interface'),
            protocol: getElementText(rule, 'protocol') || 'any',
            descr: getElementText(rule, 'descr'),
            source: getElementText(rule.querySelector('source'), 'network') || 
                    getElementText(rule.querySelector('source'), 'address') || 'any',
            destination: getElementText(rule.querySelector('destination'), 'network') || 
                        getElementText(rule.querySelector('destination'), 'address') || 'any'
        });
    });
    
    // Parse NAT Rules
    const natRules = xmlDoc.querySelectorAll('nat > rule');
    natRules.forEach(rule => {
        config.firewall.nat.push({
            interface: getElementText(rule, 'interface'),
            protocol: getElementText(rule, 'protocol'),
            destination: getElementText(rule.querySelector('destination'), 'port'),
            target: getElementText(rule, 'target'),
            localPort: getElementText(rule, 'local-port'),
            descr: getElementText(rule, 'descr')
        });
    });
    
    // Parse IPsec Configuration - FIXED: Extract remote subnets properly
    const preSharedKeys = xmlDoc.querySelectorAll('OPNsense IPsec preSharedKeys > preSharedKey');
    preSharedKeys.forEach(psk => {
        config.ipsec.psk.push({
            ident: getElementText(psk, 'ident'),
            remote_ident: getElementText(psk, 'remote_ident'),
            keyType: getElementText(psk, 'keyType')
        });
    });
    
    // Parse IPsec tunnels with their remote subnets
    const connections = xmlDoc.querySelectorAll('OPNsense Swanctl Connections > Connection');
    connections.forEach(conn => {
        const uuid = conn.getAttribute('uuid');
        const description = getElementText(conn, 'description');
        const remoteAddr = getElementText(conn, 'remote_addrs');
        const remotePort = getElementText(conn, 'remote_port');
        const proposals = getElementText(conn, 'proposals');
        const enabled = getElementText(conn, 'enabled') === '1';
        
        // Find all child tunnels for this connection and extract remote subnets
        const children = xmlDoc.querySelectorAll(`OPNsense Swanctl children > child[connection="${uuid}"]`);
        const remoteSubnets = [];
        const localSubnets = [];
        
        children.forEach(child => {
            const remoteTs = getElementText(child, 'remote_ts');
            const localTs = getElementText(child, 'local_ts');
            if (remoteTs && !remoteSubnets.includes(remoteTs)) {
                remoteSubnets.push(remoteTs);
            }
            if (localTs && !localSubnets.includes(localTs)) {
                localSubnets.push(localTs);
            }
        });
        
        config.ipsec.tunnels.push({
            description: description || `Tunnel ${remoteAddr}`,
            remote_addr: remoteAddr,
            remote_port: remotePort,
            proposals: proposals,
            enabled: enabled,
            remoteSubnets: remoteSubnets,
            localSubnets: localSubnets
        });
    });
    
    // Parse DHCP Configuration
    const dhcpConfigs = xmlDoc.querySelectorAll('dhcpd > *');
    dhcpConfigs.forEach(dhcp => {
        const tag = dhcp.tagName;
        if (getElementText(dhcp, 'enable') === '1') {
            config.dhcp.push({
                interface: tag,
                range: `${getElementText(dhcp.querySelector('range'), 'from')} - ${getElementText(dhcp.querySelector('range'), 'to')}`,
                gateway: getElementText(dhcp, 'gateway'),
                dnsServers: []
            });
            
            const dnsServers = dhcp.querySelectorAll('dnsserver');
            dnsServers.forEach(dns => {
                config.dhcp[config.dhcp.length - 1].dnsServers.push(dns.textContent);
            });
        }
    });
    
    // Parse Gateways
    const gateways = xmlDoc.querySelectorAll('OPNsense Gateways > gateway_item');
    gateways.forEach(gw => {
        config.gateways.push({
            name: getElementText(gw, 'name'),
            interface: getElementText(gw, 'interface'),
            gateway: getElementText(gw, 'gateway') || 'dynamic',
            priority: getElementText(gw, 'priority')
        });
    });
    
    // Parse Gateway Groups
    const gatewayGroups = xmlDoc.querySelectorAll('gateways > gateway_group');
    gatewayGroups.forEach(group => {
        const items = group.querySelectorAll('item');
        const members = [];
        items.forEach(item => {
            const parts = item.textContent.split('|');
            members.push({
                name: parts[0],
                tier: parts[1]
            });
        });
        
        config.gateways.push({
            name: getElementText(group, 'name'),
            type: 'group',
            members: members,
            trigger: getElementText(group, 'trigger')
        });
    });
    
    // Parse Services
    const unbound = xmlDoc.querySelector('OPNsense unboundplus general');
    config.services.unbound = {
        enabled: getElementText(unbound, 'enabled') === '1',
        port: getElementText(unbound, 'port')
    };
    
    const dnsmasq = xmlDoc.querySelector('dnsmasq');
    config.services.dnsmasq = {
        enabled: getElementText(dnsmasq, 'enable') === '1'
    };
    
    // Parse NTP
    const ntp = xmlDoc.querySelector('ntpd');
    if (ntp) {
        config.ntp.servers = getElementText(ntp, 'ispool');
    }
    
    return config;
}

function getElementText(parent, tagName) {
    if (!parent) return '';
    const element = parent.querySelector(tagName);
    return element ? element.textContent.trim() : '';
}

function displayReport() {
    document.getElementById('reportSiteName').textContent = siteName;
    document.getElementById('reportDate').textContent = new Date().toLocaleString('en-MY', {
        timeZone: 'Asia/Kuala_Lumpur',
        dateStyle: 'long',
        timeStyle: 'short'
    });
    
    const reportContent = document.getElementById('reportContent');
    reportContent.innerHTML = '';
    
    // Generate all sections
    const sections = [
        createSystemInfoSection(),
        createInterfacesSection(),
        createVLANsSection(),
        createFirewallRulesSection(),
        createNATRulesSection(),
        createIPsecSection(),
        createDHCPSection(),
        createGatewaysSection(),
        createServicesSection()
    ];
    
    sections.forEach(section => {
        reportContent.appendChild(section);
    });
    
    // Calculate pagination
    totalPages = Math.ceil(sections.length / itemsPerPage);
    currentPage = 1;
    updatePagination();
}

function createSystemInfoSection() {
    const section = document.createElement('div');
    section.className = 'section';
    section.innerHTML = `
        <div class="section-title">System Information</div>
        <div class="section-content">
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Hostname</div>
                    <div class="info-value">${parsedConfig.system.hostname || 'N/A'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Domain</div>
                    <div class="info-value">${parsedConfig.system.domain || 'N/A'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Timezone</div>
                    <div class="info-value">${parsedConfig.system.timezone || 'N/A'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">WebGUI</div>
                    <div class="info-value">${parsedConfig.system.webgui.protocol || 'https'}:${parsedConfig.system.webgui.port || '443'}</div>
                </div>
            </div>
            <h4 style="margin: 1.5rem 0 1rem 0; color: var(--text-primary);">DNS Configuration</h4>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Primary DNS</th>
                        <th>Secondary DNS</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>${parsedConfig.system.dnsServers[0] || 'N/A'}</td>
                        <td>${parsedConfig.system.dnsServers[1] || 'N/A'}</td>
                    </tr>
                </tbody>
            </table>
        </div>
    `;
    return section;
}

function createInterfacesSection() {
    const section = document.createElement('div');
    section.className = 'section';
    section.innerHTML = `
        <div class="section-title">Network Interfaces</div>
        <div class="section-content">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Interface</th>
                        <th>Description</th>
                        <th>Device</th>
                        <th>IP Address</th>
                        <th>Subnet</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${parsedConfig.interfaces.map(iface => `
                        <tr>
                            <td><strong>${iface.name.toUpperCase()}</strong></td>
                            <td>${iface.descr}</td>
                            <td>${iface.if}</td>
                            <td>${iface.ipaddr || 'DHCP'}</td>
                            <td>${iface.subnet ? '/' + iface.subnet : 'N/A'}</td>
                            <td><span class="badge ${iface.enable ? 'badge-success' : 'badge-error'}">${iface.enable ? 'Enabled' : 'Disabled'}</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
    return section;
}

function createVLANsSection() {
    const section = document.createElement('div');
    section.className = 'section';
    section.innerHTML = `
        <div class="section-title">VLAN Configuration</div>
        <div class="section-content">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>VLAN Tag</th>
                        <th>Description</th>
                        <th>Parent Interface</th>
                        <th>Interface Name</th>
                    </tr>
                </thead>
                <tbody>
                    ${parsedConfig.vlans.map(vlan => `
                        <tr>
                            <td><span class="badge badge-info">${vlan.tag}</span></td>
                            <td>${vlan.descr}</td>
                            <td>${vlan.if}</td>
                            <td>${vlan.vlanif}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
    return section;
}

function createFirewallRulesSection() {
    const section = document.createElement('div');
    section.className = 'section';
    
    // Group rules by interface
    const rulesByInterface = {};
    parsedConfig.firewall.rules.forEach(rule => {
        if (!rulesByInterface[rule.interface]) {
            rulesByInterface[rule.interface] = [];
        }
        rulesByInterface[rule.interface].push(rule);
    });
    
    let rulesHTML = '';
    Object.keys(rulesByInterface).forEach(iface => {
        rulesHTML += `
            <div style="margin-bottom: 1.5rem;">
                <h4 style="margin-bottom: 0.75rem; color: var(--solaris-orange);">Interface: ${iface.toUpperCase()}</h4>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Action</th>
                            <th>Protocol</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rulesByInterface[iface].map(rule => `
                            <tr>
                                <td><span class="badge ${rule.type === 'pass' ? 'badge-success' : 'badge-error'}">${rule.type === 'pass' ? 'PASS' : 'BLOCK'}</span></td>
                                <td>${rule.protocol}</td>
                                <td>${rule.source}</td>
                                <td>${rule.destination}</td>
                                <td>${rule.descr || '-'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    });
    
    section.innerHTML = `
        <div class="section-title">Firewall Rules (${parsedConfig.firewall.rules.length} rules)</div>
        <div class="section-content">
            ${rulesHTML}
        </div>
    `;
    return section;
}

function createNATRulesSection() {
    const section = document.createElement('div');
    section.className = 'section';
    section.innerHTML = `
        <div class="section-title">NAT Rules (${parsedConfig.firewall.nat.length} rules)</div>
        <div class="section-content">
            ${parsedConfig.firewall.nat.length > 0 ? `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Interface</th>
                            <th>Protocol</th>
                            <th>External Port</th>
                            <th>Internal Target</th>
                            <th>Local Port</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${parsedConfig.firewall.nat.map(rule => `
                            <tr>
                                <td>${rule.interface.toUpperCase()}</td>
                                <td>${rule.protocol}</td>
                                <td>${rule.destination}</td>
                                <td>${rule.target}</td>
                                <td>${rule.localPort}</td>
                                <td>${rule.descr || '-'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            ` : '<p class="alert alert-info">No NAT rules configured</p>'}
        </div>
    `;
    return section;
}

function createIPsecSection() {
    const section = document.createElement('div');
    section.className = 'section';
    section.innerHTML = `
        <div class="section-title">IPsec VPN Tunnels (${parsedConfig.ipsec.tunnels.length} tunnels)</div>
        <div class="section-content">
            ${parsedConfig.ipsec.tunnels.map(tunnel => `
                <div style="margin-bottom: 1.5rem; padding: 1rem; background: var(--bg-tertiary); border-radius: 8px; border-left: 4px solid var(--solaris-orange);">
                    <h4 style="margin-bottom: 1rem; color: var(--text-primary);">${tunnel.description}</h4>
                    <div class="info-grid">
                        <div class="info-item">
                            <div class="info-label">Remote Address</div>
                            <div class="info-value">${tunnel.remote_addr}:${tunnel.remote_port}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Status</div>
                            <div class="info-value"><span class="badge ${tunnel.enabled ? 'badge-success' : 'badge-error'}">${tunnel.enabled ? 'Enabled' : 'Disabled'}</span></div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Proposal</div>
                            <div class="info-value">${tunnel.proposals}</div>
                        </div>
                    </div>
                    <div style="margin-top: 1rem;">
                        <strong style="color: var(--text-secondary);">Local Subnets:</strong>
                        <div style="margin-top: 0.5rem;">
                            ${tunnel.localSubnets && tunnel.localSubnets.length > 0 ? tunnel.localSubnets.map(subnet => `<span class="badge badge-info" style="margin-right: 0.5rem; margin-bottom: 0.25rem;">${subnet}</span>`).join('') : '<span style="color: var(--text-muted); margin-left: 0.5rem;">N/A</span>'}
                        </div>
                    </div>
                    <div style="margin-top: 1rem;">
                        <strong style="color: var(--text-secondary);">Remote Subnets:</strong>
                        <div style="margin-top: 0.5rem;">
                            ${tunnel.remoteSubnets && tunnel.remoteSubnets.length > 0 ? tunnel.remoteSubnets.map(subnet => `<span class="badge badge-success" style="margin-right: 0.5rem; margin-bottom: 0.25rem;">${subnet}</span>`).join('') : '<span style="color: var(--text-muted); margin-left: 0.5rem;">N/A</span>'}
                        </div>
                    </div>
                </div>
            `).join('')}
            ${parsedConfig.ipsec.tunnels.length === 0 ? '<p class="alert alert-info">No IPsec tunnels configured</p>' : ''}
        </div>
    `;
    return section;
}

function createDHCPSection() {
    const section = document.createElement('div');
    section.className = 'section';
    section.innerHTML = `
        <div class="section-title">DHCP Configuration (${parsedConfig.dhcp.length} scopes)</div>
        <div class="section-content">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Interface</th>
                        <th>IP Range</th>
                        <th>Gateway</th>
                        <th>DNS Servers</th>
                    </tr>
                </thead>
                <tbody>
                    ${parsedConfig.dhcp.map(dhcp => `
                        <tr>
                            <td><strong>${dhcp.interface.toUpperCase()}</strong></td>
                            <td>${dhcp.range}</td>
                            <td>${dhcp.gateway}</td>
                            <td>${dhcp.dnsServers.join(', ')}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
    return section;
}

function createGatewaysSection() {
    const section = document.createElement('div');
    section.className = 'section';
    section.innerHTML = `
        <div class="section-title">Gateway Configuration</div>
        <div class="section-content">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Interface</th>
                        <th>Gateway IP</th>
                        <th>Priority</th>
                    </tr>
                </thead>
                <tbody>
                    ${parsedConfig.gateways.map(gw => `
                        <tr>
                            <td><strong>${gw.name}</strong></td>
                            <td><span class="badge ${gw.type === 'group' ? 'badge-warning' : 'badge-info'}">${gw.type === 'group' ? 'Group' : 'Single'}</span></td>
                            <td>${gw.interface || 'N/A'}</td>
                            <td>${gw.gateway || 'N/A'}</td>
                            <td>${gw.priority || gw.trigger ? (gw.trigger ? `Failover: ${gw.trigger}` : 'N/A') : 'N/A'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
    return section;
}

function createServicesSection() {
    const section = document.createElement('div');
    section.className = 'section';
    section.innerHTML = `
        <div class="section-title">Services Status</div>
        <div class="section-content">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Service</th>
                        <th>Status</th>
                        <th>Port</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Unbound DNS</td>
                        <td><span class="badge ${parsedConfig.services.unbound.enabled ? 'badge-success' : 'badge-error'}">${parsedConfig.services.unbound.enabled ? 'Enabled' : 'Disabled'}</span></td>
                        <td>${parsedConfig.services.unbound.port || '53'}</td>
                    </tr>
                    <tr>
                        <td>Dnsmasq</td>
                        <td><span class="badge ${parsedConfig.services.dnsmasq.enabled ? 'badge-success' : 'badge-error'}">${parsedConfig.services.dnsmasq.enabled ? 'Enabled' : 'Disabled'}</span></td>
                        <td>53053</td>
                    </tr>
                </tbody>
            </table>
        </div>
    `;
    return section;
}

function updatePagination() {
    const sections = document.querySelectorAll('.section');
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    
    sections.forEach((section, index) => {
        if (index >= startIndex && index < endIndex) {
            section.style.display = 'block';
        } else {
            section.style.display = 'none';
        }
    });
    
    document.getElementById('currentPage').textContent = currentPage;
    document.getElementById('totalPages').textContent = totalPages;
    document.getElementById('prevBtn').disabled = currentPage === 1;
    document.getElementById('nextBtn').disabled = currentPage === totalPages;
}

function previousPage() {
    if (currentPage > 1) {
        currentPage--;
        updatePagination();
        window.scrollTo(0, 0);
    }
}

function nextPage() {
    if (currentPage < totalPages) {
        currentPage++;
        updatePagination();
        window.scrollTo(0, 0);
    }
}

// FIXED: Proper PDF generation using jsPDF and html2canvas
async function downloadPDF() {
    try {
        // Show loading state
        const btn = document.querySelector('button[onclick="downloadPDF()"]');
        const originalText = btn.textContent;
        btn.textContent = 'Generating PDF...';
        btn.disabled = true;
        
        // Load libraries dynamically if not already loaded
        if (typeof window.jspdf === 'undefined' || typeof window.html2canvas === 'undefined') {
            await loadScript('https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js');
            await loadScript('https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js');
        }
        
        const { jsPDF } = window.jspdf;
        
        // Create a new PDF document (A4 size)
        const pdf = new jsPDF('p', 'mm', 'a4');
        const pageWidth = pdf.internal.pageSize.getWidth();
        const pageHeight = pdf.internal.pageSize.getHeight();
        
        // Get the report content
        const reportHeader = document.querySelector('.report-header');
        const reportContent = document.getElementById('reportContent');
        const sections = document.querySelectorAll('.section');
        
        // Add header to first page
        pdf.setFillColor(242, 101, 34); // Solaris orange
        pdf.rect(0, 0, pageWidth, 15, 'F');
        
        pdf.setTextColor(255, 255, 255);
        pdf.setFontSize(16);
        pdf.text('Firewall Infrastructure Upgrade Configuration Report', 10, 10);
        
        pdf.setFontSize(11);
        pdf.text(`Site Name: ${siteName}`, 10, 20);
        pdf.text(`Generated: ${new Date().toLocaleString()}`, 10, 26);
        
        let yPos = 35;
        let pageNum = 1;
        
        // Process each section
        for (let i = 0; i < sections.length; i++) {
            const section = sections[i];
            const sectionTitle = section.querySelector('.section-title').textContent;
            const sectionContent = section.querySelector('.section-content');
            
            // Check if we need a new page
            if (yPos > pageHeight - 40) {
                pdf.addPage();
                yPos = 20;
                pageNum++;
                
                // Add header
                pdf.setFillColor(242, 101, 34);
                pdf.rect(0, 0, pageWidth, 10, 'F');
                pdf.setTextColor(255, 255, 255);
                pdf.setFontSize(10);
                pdf.text(`Firewall Report - ${siteName}`, 10, 7);
                
                // Add footer with page number
                pdf.setFontSize(9);
                pdf.text(`Page ${pageNum}`, pageWidth - 20, pageHeight - 7);
                
                yPos = 25;
            }
            
            // Add section title
            pdf.setFillColor(242, 101, 34);
            pdf.rect(10, yPos - 5, pageWidth - 20, 8, 'F');
            pdf.setTextColor(255, 255, 255);
            pdf.setFontSize(12);
            pdf.text(sectionTitle, 12, yPos);
            
            yPos += 12;
            
            // Convert section content to text and add to PDF
            const tables = sectionContent.querySelectorAll('.data-table');
            const infoItems = sectionContent.querySelectorAll('.info-item');
            
            // Process info grids
            if (infoItems.length > 0) {
                pdf.setFontSize(9);
                pdf.setTextColor(50, 50, 50);
                
                infoItems.forEach((item, idx) => {
                    const label = item.querySelector('.info-label')?.textContent || '';
                    const value = item.querySelector('.info-value')?.textContent || '';
                    
                    if (yPos > pageHeight - 30) {
                        pdf.addPage();
                        yPos = 20;
                        pageNum++;
                        pdf.setFontSize(9);
                        pdf.text(`Page ${pageNum}`, pageWidth - 20, pageHeight - 7);
                    }
                    
                    pdf.text(`${label}: ${value}`, 15, yPos);
                    yPos += 6;
                });
                
                yPos += 5;
            }
            
            // Process tables
            tables.forEach(table => {
                const headers = [];
                const rows = [];
                
                // Extract headers
                const headerCells = table.querySelectorAll('thead th');
                headerCells.forEach(cell => {
                    headers.push(cell.textContent);
                });
                
                // Extract rows
                const bodyRows = table.querySelectorAll('tbody tr');
                bodyRows.forEach(row => {
                    const rowData = [];
                    const cells = row.querySelectorAll('td');
                    cells.forEach(cell => {
                        // Get text content, removing badge text formatting
                        const text = cell.textContent.replace(/\n/g, ' ').trim();
                        rowData.push(text);
                    });
                    rows.push(rowData);
                });
                
                // Add table to PDF
                if (rows.length > 0) {
                    // Check if we need a new page
                    if (yPos + (rows.length * 6) + 20 > pageHeight) {
                        pdf.addPage();
                        yPos = 20;
                        pageNum++;
                        pdf.setFontSize(9);
                        pdf.text(`Page ${pageNum}`, pageWidth - 20, pageHeight - 7);
                    }
                    
                    pdf.autoTable({
                        head: [headers],
                        body: rows,
                        startY: yPos,
                        margin: { left: 10, right: 10 },
                        headStyles: { 
                            fillColor: [30, 33, 40], 
                            textColor: 255,
                            fontSize: 8
                        },
                        bodyStyles: { 
                            textColor: 50,
                            fontSize: 8
                        },
                        alternateRowStyles: { 
                            fillColor: [245, 245, 245]
                        },
                        didDrawPage: function(data) {
                            // Add footer
                            pdf.setFontSize(9);
                            pdf.text(`Page ${pageNum}`, pageWidth - 20, pageHeight - 7);
                        }
                    });
                    
                    yPos = pdf.lastAutoTable.finalY + 10;
                }
            });
            
            yPos += 10;
        }
        
        // Add final footer
        const totalPages = pdf.internal.getNumberOfPages();
        for (let i = 1; i <= totalPages; i++) {
            pdf.setPage(i);
            pdf.setFontSize(9);
            pdf.setTextColor(100);
            pdf.text(`Page ${i} of ${totalPages}`, pageWidth - 30, pageHeight - 7);
        }
        
        // Save the PDF
        const filename = `Firewall_Report_${siteName.replace(/\s+/g, '_')}_${new Date().toISOString().split('T')[0]}.pdf`;
        pdf.save(filename);
        
        // Restore button
        btn.textContent = originalText;
        btn.disabled = false;
        
    } catch (error) {
        console.error('PDF generation error:', error);
        alert('Error generating PDF: ' + error.message);
        
        // Restore button
        const btn = document.querySelector('button[onclick="downloadPDF()"]');
        btn.textContent = 'Download PDF';
        btn.disabled = false;
    }
}

// Helper function to load scripts
function loadScript(src) {
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = src;
        script.onload = resolve;
        script.onerror = reject;
        document.head.appendChild(script);
    });
}

function resetApp() {
    if (confirm('Are you sure you want to create a new report?')) {
        location.reload();
    }
}

// Add drag and drop visual feedback
['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}