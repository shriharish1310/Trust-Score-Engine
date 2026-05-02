const API_BASE = "http://127.0.0.1:8000";

const els = {
    activeTabButton: document.getElementById("activeTabButton"),
    batchButton: document.getElementById("batchButton"),
    batchCount: document.getElementById("batchCount"),
    batchInput: document.getElementById("batchInput"),
    batchList: document.getElementById("batchList"),
    batchPanel: document.getElementById("batchPanel"),
    batchResults: document.getElementById("batchResults"),
    reasons: document.getElementById("reasons"),
    reasonCount: document.getElementById("reasonCount"),
    risk: document.getElementById("risk"),
    runBatchButton: document.getElementById("runBatchButton"),
    scanButton: document.getElementById("scanButton"),
    score: document.getElementById("score"),
    service: document.getElementById("service"),
    signalCount: document.getElementById("signalCount"),
    signals: document.getElementById("signals"),
    status: document.getElementById("status"),
    urlInput: document.getElementById("urlInput"),
    verdict: document.getElementById("verdict"),
};

function setBusy(isBusy) {
    els.scanButton.disabled = isBusy;
    els.runBatchButton.disabled = isBusy;
    els.activeTabButton.disabled = isBusy;
}

function setStatus(message, isError = false) {
    els.status.textContent = message || "";
    els.status.classList.toggle("error", Boolean(isError));
}

function normalizeUrl(raw) {
    const value = String(raw || "").trim();
    if (!value) {
        return "";
    }
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
        return value;
    }
    return `https://${value}`;
}

function isScannableUrl(url) {
    return /^https?:\/\//i.test(url);
}

async function getActiveTabUrl() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.url || "";
}

function formatRisk(value) {
    if (typeof value !== "number" || Number.isNaN(value)) {
        return "--";
    }
    return `${Math.round(value * 100)}%`;
}

function verdictClass(verdict) {
    const normalized = String(verdict || "").toLowerCase();
    if (normalized === "safe") {
        return "safe";
    }
    if (normalized === "suspicious") {
        return "suspicious";
    }
    if (normalized === "dangerous") {
        return "dangerous";
    }
    return "neutral";
}

function setSummary(result) {
    const verdict = result?.verdict || "Waiting";
    els.verdict.textContent = verdict;
    els.verdict.className = `verdict ${verdictClass(verdict)}`;
    els.score.textContent = typeof result?.trust_score === "number" ? String(result.trust_score) : "--";
    els.risk.textContent = formatRisk(result?.risk?.final);
}

function reasonText(reason) {
    if (typeof reason === "string") {
        return reason;
    }
    return reason?.message || reason?.msg || reason?.reason || JSON.stringify(reason);
}

function renderReasons(reasons) {
    const items = Array.isArray(reasons) ? reasons : [];
    els.reasons.innerHTML = "";
    els.reasonCount.textContent = String(items.length);

    if (items.length === 0) {
        const li = document.createElement("li");
        li.textContent = "No rule-based reasons triggered.";
        els.reasons.appendChild(li);
        return;
    }

    for (const reason of items) {
        const li = document.createElement("li");
        li.textContent = reasonText(reason);
        els.reasons.appendChild(li);
    }
}

function signalLabel(name) {
    return String(name || "signal")
        .replaceAll("_", " ")
        .replace(/\b\w/g, (char) => char.toUpperCase());
}

function renderSignal(signal) {
    const card = document.createElement("div");
    card.className = "signal";

    const score = Number.isFinite(signal?.score) ? signal.score : 0;
    const risk = Number.isFinite(signal?.risk) ? signal.risk : 0;

    card.innerHTML = `
        <div class="signal-main">
            <div class="signal-title"></div>
            <div class="signal-meta">
                <span>Score ${score}</span>
                <span>Risk ${formatRisk(risk)}</span>
            </div>
            <div class="meter"><div class="meter-fill"></div></div>
            <div class="signal-detail"></div>
        </div>
    `;
    card.querySelector(".signal-title").textContent = signalLabel(signal?.name);
    card.querySelector(".meter-fill").style.width = `${Math.max(0, Math.min(100, score))}%`;
    card.querySelector(".signal-detail").textContent = signal?.detail || "No detail returned.";
    return card;
}

function renderSignals(signals) {
    const items = Array.isArray(signals) ? signals : [];
    els.signals.innerHTML = "";
    els.signalCount.textContent = String(items.length);

    if (items.length === 0) {
        const empty = document.createElement("div");
        empty.className = "signal-detail";
        empty.textContent = "No signal results yet.";
        els.signals.appendChild(empty);
        return;
    }

    for (const signal of items) {
        els.signals.appendChild(renderSignal(signal));
    }
}

function renderResult(result) {
    setSummary(result);
    renderSignals(result?.signals);
    renderReasons(result?.reasons);
    els.service.textContent = result?.product_name || "Local API";
}

function parseNdjson(buffer) {
    const lines = buffer.split("\n");
    const tail = lines.pop() || "";
    const events = [];
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed) {
            events.push(JSON.parse(trimmed));
        }
    }
    return { events, tail };
}

async function scanUrl(url) {
    const response = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
    });

    if (!response.ok) {
        const text = await response.text();
        throw new Error(`API error ${response.status}: ${text}`);
    }

    const partial = { url, signals: [], reasons: [] };
    if (!response.body) {
        const text = await response.text();
        const lastEvent = text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)).pop();
        return lastEvent?.result || partial;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let finalResult = null;

    for (;;) {
        const { value, done } = await reader.read();
        if (done) {
            break;
        }

        buffer += decoder.decode(value, { stream: true });
        const parsed = parseNdjson(buffer);
        buffer = parsed.tail;

        for (const event of parsed.events) {
            const eventType = event.type || event.event;
            if (eventType === "scan_started") {
                setStatus(`Scanning ${event.url}`);
            } else if (eventType === "signal_result") {
                partial.signals.push(event.signal || event.result?.data || { name: event.name, detail: event.result?.error });
                renderSignals(partial.signals);
            } else if (eventType === "scan_complete") {
                finalResult = event.result?.raw || event.result;
                renderResult(finalResult);
            }
        }
    }

    buffer += decoder.decode();
    if (buffer.trim()) {
        for (const line of buffer.trim().split("\n")) {
            const event = JSON.parse(line);
            const eventType = event.type || event.event;
            if (eventType === "scan_complete") {
                finalResult = event.result?.raw || event.result;
            }
        }
    }

    return finalResult || partial;
}

async function scanCurrentInput() {
    const url = normalizeUrl(els.urlInput.value);
    els.urlInput.value = url;

    if (!isScannableUrl(url)) {
        throw new Error("Enter an http or https URL.");
    }

    setBusy(true);
    setStatus("Starting scan...");
    renderSignals([]);
    renderReasons([]);

    try {
        const result = await scanUrl(url);
        renderResult(result);
        setStatus("Scan complete.");
    } finally {
        setBusy(false);
    }
}

async function loadActiveTab() {
    const url = await getActiveTabUrl();
    els.urlInput.value = url;
    if (!isScannableUrl(url)) {
        setStatus("Open an http or https page to scan the active tab.", true);
        return;
    }
    await scanCurrentInput();
}

async function scanBatch() {
    const urls = els.batchInput.value
        .split(/\r?\n/)
        .map(normalizeUrl)
        .filter(Boolean);

    if (urls.length === 0) {
        throw new Error("Enter at least one URL for batch scanning.");
    }

    setBusy(true);
    setStatus("Running batch scan...");

    try {
        const response = await fetch(`${API_BASE}/api/analyze/batch`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ urls }),
        });
        if (!response.ok) {
            const text = await response.text();
            throw new Error(`API error ${response.status}: ${text}`);
        }
        const results = await readBatchStream(response);
        renderBatchResults(results);
        setStatus("Batch scan complete.");
    } finally {
        setBusy(false);
    }
}

async function readBatchStream(response) {
    if (!response.body) {
        const text = await response.text();
        const lines = text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
        const complete = lines.findLast((event) => event.type === "batch_complete");
        return (complete?.results || []).map((result) => result.raw || result);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const results = [];
    let buffer = "";

    for (;;) {
        const { value, done } = await reader.read();
        if (done) {
            break;
        }

        buffer += decoder.decode(value, { stream: true });
        const parsed = parseNdjson(buffer);
        buffer = parsed.tail;

        for (const event of parsed.events) {
            if (event.type === "url_complete") {
                results[event.index] = event.result?.raw || event.result;
                renderBatchResults(results.filter(Boolean));
            } else if (event.type === "batch_started") {
                setStatus(`Running batch scan: 0/${event.total}`);
            } else if (event.type === "batch_complete") {
                return (event.results || []).map((result) => result.raw || result);
            }
        }
    }

    return results.filter(Boolean);
}

function renderBatchResults(results) {
    els.batchList.innerHTML = "";
    els.batchCount.textContent = String(results.length);
    els.batchResults.classList.toggle("hidden", results.length === 0);

    for (const result of results) {
        const item = document.createElement("div");
        item.className = "batch-item";
        item.innerHTML = `
            <div class="batch-url"></div>
            <div class="batch-meta">
                <span></span>
                <span></span>
                <span></span>
            </div>
        `;
        item.querySelector(".batch-url").textContent = result.url || result.url_input || "Unknown URL";
        const spans = item.querySelectorAll(".batch-meta span");
        spans[0].textContent = result.verdict || "UNKNOWN";
        spans[1].textContent = `Score ${result.trust_score ?? "--"}`;
        spans[2].textContent = `Risk ${formatRisk(result?.risk?.final)}`;
        els.batchList.appendChild(item);
    }
}

els.scanButton.addEventListener("click", () => {
    scanCurrentInput().catch((error) => setStatus(error.message, true));
});

els.activeTabButton.addEventListener("click", () => {
    loadActiveTab().catch((error) => setStatus(error.message, true));
});

els.batchButton.addEventListener("click", () => {
    els.batchPanel.classList.toggle("hidden");
});

els.runBatchButton.addEventListener("click", () => {
    scanBatch().catch((error) => setStatus(error.message, true));
});

els.urlInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        scanCurrentInput().catch((error) => setStatus(error.message, true));
    }
});

renderSignals([]);
renderReasons([]);
loadActiveTab().catch((error) => setStatus(error.message, true));
