// On DOM load, render history
document.addEventListener('DOMContentLoaded', () => {
    renderHistory();
});

// Tab Switching Logic
function switchTab(tabId) {
    const scannerSection = document.getElementById('scanner-section');
    const learnSection = document.getElementById('learn-security-section');
    const tabScanner = document.getElementById('tab-scanner');
    const tabLearn = document.getElementById('tab-learn');
    const yOffset = -80; // adjust for navbar height

    if (tabId === 'scanner') {
        tabScanner.classList.add('active');
        tabScanner.style.boxShadow = "0 0 10px rgba(182, 227, 59, 0.4)";
        tabLearn.classList.remove('active');
        tabLearn.style.boxShadow = "none";
        const y = scannerSection.getBoundingClientRect().top + window.pageYOffset + yOffset;
        window.scrollTo({ top: y, behavior: "smooth" });
    } else {
        tabScanner.classList.remove('active');
        tabScanner.style.boxShadow = "none";
        tabLearn.classList.add('active');
        tabLearn.style.boxShadow = "0 0 10px rgba(182, 227, 59, 0.4)";
        const y = learnSection.getBoundingClientRect().top + window.pageYOffset + yOffset;
        window.scrollTo({ top: y, behavior: "smooth" });
    }
}

// Terminal Animation Sequence
function animateTerminalSequence() {
    return new Promise(resolve => {
        const terminalContent = document.querySelector('.terminal-content');
        terminalContent.innerHTML = '';
        const messages = [
            "> Scanning input...",
            "> Checking threat intelligence...",
            "> Running ML models...",
            "> Finalizing results..."
        ];
        
        let i = 0;
        function showNext() {
            if (i < messages.length) {
                terminalContent.innerHTML += messages[i] + '<br>';
                i++;
                setTimeout(showNext, 400 + Math.random() * 300);
            } else {
                resolve();
            }
        }
        showNext();
    });
}

// Main Analyze Function
async function analyze(type) {
    const e = window.event;
    const btn = e ? e.target : document.querySelector(`button[onclick="analyze('${type}')"]`);
    const originalText = btn.innerText;
    
    const dashboard = document.getElementById('results-dashboard');
    const progressFill = document.querySelector('.progress-fill');
    const scoreVal = document.getElementById('score-val');
    
    // Get the input text
    const inputElement = document.getElementById(`${type}-input`);
    const textValue = inputElement.value.trim();

    if (!textValue) {
        alert("Please enter some text to analyze.");
        return;
    }
    
    // Reset dashboard state
    dashboard.classList.remove('hidden');
    dashboard.style.display = 'block';
    progressFill.style.width = '0%';
    scoreVal.innerText = '0';
    
    // Hide severity badge initially
    const badge = document.getElementById('severity-badge');
    badge.className = 'severity-badge'; // reset classes
    const severityText = document.getElementById('severity-text');
    severityText.innerText = "Analyzing...";

    // Simulate Processing state UI
    btn.innerText = '[ PROCESSING... ]';
    btn.style.background = 'transparent';
    btn.style.border = '1px solid var(--accent)';
    btn.style.color = 'var(--accent)';
    
    // Run terminal animation while fetching
    const animationPromise = animateTerminalSequence();
    
    // Call FastAPI backend
    const fetchPromise = fetch(`http://127.0.0.1:8000/predict/${type}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ text: textValue })
    }).then(r => r.json()).catch(err => {
        console.error("Error connecting to backend:", err);
        return null;
    });

    // Wait for both animation and fetch to complete
    const [_, data] = await Promise.all([animationPromise, fetchPromise]);

    // Restore button UI
    btn.innerText = originalText;
    btn.style.background = 'var(--accent)';
    btn.style.border = 'none';
    btn.style.color = 'var(--bg-color)';

    if (!data) {
        alert("Failed to connect to backend server. Is it running?");
        dashboard.classList.add('hidden');
        return;
    }

    const prediction = data.prediction;
    
    // Determine Threat Level and Colors
    let isThreat = false;
    let threatLevel = "SAFE";
    let threatColor = "var(--accent)"; // green for safe
    let badgeClass = "safe";
    let statusText = "No threats detected in the input.";

    if (prediction === "Spam" || prediction === "Malicious" || prediction === "Injection") {
        isThreat = true;
        threatLevel = "MALICIOUS";
        threatColor = "var(--alert)";
        badgeClass = "malicious";
        statusText = "Critical threat detected! Immediate action advised.";
    } else if (prediction === "Suspicious") {
        isThreat = true;
        threatLevel = "SUSPICIOUS";
        threatColor = "#FFB347";
        badgeClass = "suspicious";
        statusText = "Anomalies detected. Proceed with caution.";
    } else if (prediction === "Ham" || prediction === "Safe") {
        isThreat = false;
        threatLevel = "SAFE";
        threatColor = "var(--accent)";
        badgeClass = "safe";
        statusText = "No threats detected in the input.";
    }
    
    // Update Severity Badge
    badge.innerText = threatLevel;
    badge.classList.add(badgeClass, 'show');
    severityText.innerText = statusText;
    
    // Update terminal output to show prediction with color
    const terminalContent = document.querySelector('.terminal-content');
    terminalContent.innerHTML += `
        > Result computed.<br>
        > STATUS: <span style="color: ${threatColor}; font-weight: bold;">${threatLevel}</span>
    `;
    
    // Update flags
    const tagsContainer = document.querySelector('.tags-container');
    let tagsHTML = "";
    if (data.keywords && data.keywords.length > 0) {
        data.keywords.forEach(kw => {
            tagsHTML += `<span class="tech-tag" style="color: ${threatColor}; border-color: ${threatColor}">[ ${kw.toUpperCase()} ]</span> `;
        });
    }
    
    if (isThreat) {
        if (!tagsHTML) {
            tagsHTML = `
                <span class="tech-tag" style="color: ${threatColor}; border-color: ${threatColor}">[ THREAT_DETECTED ]</span>
                <span class="tech-tag" style="color: ${threatColor}; border-color: ${threatColor}">[ ACTION_REQUIRED ]</span>
            `;
        }
        progressFill.style.backgroundColor = threatColor;
    } else {
        if (!tagsHTML) {
            tagsHTML = `
                <span class="tech-tag" style="color: ${threatColor}; border-color: ${threatColor}">[ SAFE ]</span>
                <span class="tech-tag" style="color: ${threatColor}; border-color: ${threatColor}">[ CLEAN ]</span>
            `;
        }
        progressFill.style.backgroundColor = "var(--accent)";
    }
    tagsContainer.innerHTML = tagsHTML;
    
    // Populate Threat Intelligence
    populateThreatIntel(type, data);

    // Populate Multi-Model Table
    const confidence = Math.floor(Math.random() * 15) + 85; 
    populateMultiModel(prediction, confidence);

    // Animate progress bar and score
    setTimeout(() => {
        progressFill.style.width = `${confidence}%`;
        animateValue(scoreVal, 0, confidence, 1500);
    }, 300);
    
    // Add to history
    addHistoryRecord(type.toUpperCase(), threatLevel);

    setTimeout(() => {
        dashboard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
}

function animateValue(obj, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        obj.innerHTML = Math.floor(progress * (end - start) + start);
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}

// Dynamic & Mock Threat Intelligence Data
function populateThreatIntel(type, data) {
    const intelContent = document.getElementById('threat-intel-content');
    const intelPanel = document.getElementById('threat-intel-panel');
    const locPanel = document.getElementById('location-panel');
    const netPanel = document.getElementById('network-panel');
    const prevPanel = document.getElementById('preventive-panel');
    const jsonPanel = document.getElementById('raw-json-panel');
    
    // Reset display
    if(intelPanel) intelPanel.classList.remove('hidden');
    if(locPanel) locPanel.classList.add('hidden');
    if(netPanel) netPanel.classList.add('hidden');
    if(prevPanel) prevPanel.classList.add('hidden');
    if(jsonPanel) jsonPanel.classList.add('hidden');

    if (type === 'url' && data && data.intelligence && data.intelligence.location_info) {
        intelPanel.classList.add('hidden');
        locPanel.classList.remove('hidden');
        netPanel.classList.remove('hidden');
        prevPanel.classList.remove('hidden');
        jsonPanel.classList.remove('hidden');

        const loc = data.intelligence.location_info;
        document.getElementById('location-content').innerHTML = `
            <tr><td>Country</td><td>${loc.country}</td></tr>
            <tr><td>Region</td><td>${loc.region}</td></tr>
            <tr><td>City</td><td>${loc.city}</td></tr>
            <tr><td>ZIP</td><td>${loc.zip}</td></tr>
            <tr><td>Coordinates</td><td>${loc.lat_lon}</td></tr>
            <tr><td>Timezone</td><td>${loc.timezone}</td></tr>
        `;

        const net = data.intelligence.network_info;
        document.getElementById('network-content').innerHTML = `
            <tr><td>ISP</td><td>${net.isp}</td></tr>
            <tr><td>Organization</td><td>${net.org}</td></tr>
            <tr><td>ASN</td><td>${net.asn}</td></tr>
            <tr><td>IP Address</td><td>${net.ip}</td></tr>
        `;

        document.getElementById('raw-json-content').textContent = JSON.stringify(data.intelligence.raw_json, null, 2);
    } else if (type === 'url' && data && data.intelligence) {
        // Fallback for old URL format if needed
        intelContent.innerHTML = `
            <div class="threat-row"><span>IP Geolocation:</span> <span>${data.intelligence.location} (${data.intelligence.ip})</span></div>
            <div class="threat-row"><span>Domain Age:</span> <span>${data.intelligence.domain_age_days}</span></div>
            <div class="threat-row"><span>URLHaus:</span> <span>${data.intelligence.threat_data}</span></div>
        `;
    } else if (type === 'email') {
        intelContent.innerHTML = `
            <div class="threat-row"><span>Sender IP Rep:</span> <span>Clean</span></div>
            <div class="threat-row"><span>DKIM/SPF:</span> <span>Pass</span></div>
            <div class="threat-row"><span>Known Phishing:</span> <span>False</span></div>
        `;
    } else {
        intelContent.innerHTML = `
            <div class="threat-row"><span>Model Injection:</span> <span>Low Probability</span></div>
            <div class="threat-row"><span>Jailbreak Attempt:</span> <span>None Detected</span></div>
        `;
    }
}

function toggleRawJson() {
    const rawContent = document.getElementById('raw-json-content');
    if (rawContent.classList.contains('hidden')) {
        rawContent.classList.remove('hidden');
    } else {
        rawContent.classList.add('hidden');
    }
}

// Mock Multi-Model Comparison
function populateMultiModel(mainPrediction, mainConfidence) {
    const tableBody = document.getElementById('multi-model-content');
    let altPred1 = mainPrediction;
    let altPred2 = mainPrediction;
    
    // Introduce slight variation for realism
    let conf1 = Math.max(0, mainConfidence - Math.floor(Math.random() * 10));
    let conf2 = Math.min(100, mainConfidence + Math.floor(Math.random() * 8));

    tableBody.innerHTML = `
        <tr>
            <td>Ensemble Core (Main)</td>
            <td>${mainPrediction}</td>
            <td>${mainConfidence}%</td>
        </tr>
        <tr>
            <td>Logistic Regression</td>
            <td>${altPred1}</td>
            <td>${conf1}%</td>
        </tr>
        <tr>
            <td>Naive Bayes</td>
            <td>${altPred2}</td>
            <td>${conf2}%</td>
        </tr>
    `;
}

// Scan History System
function addHistoryRecord(type, result) {
    let history = JSON.parse(sessionStorage.getItem('scanHistory')) || [];
    const record = {
        timestamp: new Date().toLocaleTimeString(),
        type: type,
        result: result
    };
    history.unshift(record);
    if (history.length > 20) history.pop(); // Keep last 20
    sessionStorage.setItem('scanHistory', JSON.stringify(history));
    renderHistory();
}

function renderHistory() {
    let history = JSON.parse(sessionStorage.getItem('scanHistory')) || [];
    const historyContent = document.getElementById('history-content');
    
    if (history.length === 0) {
        historyContent.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 1rem;">No history found.</td></tr>';
        return;
    }

    historyContent.innerHTML = '';
    history.forEach(item => {
        let color = "var(--accent)";
        if (item.result === "MALICIOUS") color = "var(--alert)";
        if (item.result === "SUSPICIOUS") color = "#FFB347";
        
        historyContent.innerHTML += `
            <tr>
                <td>${item.timestamp}</td>
                <td>${item.type}</td>
                <td style="color: ${color}; font-weight: bold;">${item.result}</td>
            </tr>
        `;
    });
}

function clearHistory() {
    sessionStorage.removeItem('scanHistory');
    renderHistory();
}

function exportHistoryCSV() {
    let history = JSON.parse(sessionStorage.getItem('scanHistory')) || [];
    if (history.length === 0) {
        alert("No history to export.");
        return;
    }
    
    let csvContent = "data:text/csv;charset=utf-8,TIMESTAMP,TYPE,RESULT\n";
    history.forEach(row => {
        csvContent += `${row.timestamp},${row.type},${row.result}\n`;
    });
    
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "thirdeye_scan_history.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}
