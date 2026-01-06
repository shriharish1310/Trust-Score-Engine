async function getActiveTabUrl() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab?.url || "";
}

function setStatus(msg) {
    document.getElementById("status").textContent = msg || "";
}

function setVerdict(verdict) {
    const el = document.getElementById("verdict");
    el.textContent = verdict || "—";
}

function setScore(score) {
    document.getElementById("score").textContent =
        typeof score === "number" ? String(score) : "—";
}

function setReasons(reasons) {
    const ul = document.getElementById("reasons");
    ul.innerHTML = "";
    if (!Array.isArray(reasons) || reasons.length === 0) {
        const li = document.createElement("li");
        li.textContent = "No rule-based reasons triggered.";
        ul.appendChild(li);
        return;
    }
    for (const r of reasons) {
        const li = document.createElement("li");
        // Your API returns reasons as list[dict]. Handle common keys:
        const msg = r.message || r.msg || r.reason || JSON.stringify(r);
        li.textContent = msg;
        ul.appendChild(li);
    }
}

async function scoreUrl(url) {
    const endpoint = "http://127.0.0.1:8000/score";

    const resp = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
    });

    if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`API error ${resp.status}: ${text}`);
    }
    return await resp.json();
}

(async function main() {
    try {
        setStatus("");
        const url = await getActiveTabUrl();

        document.getElementById("url").textContent = url || "(no url)";

        // Avoid scoring chrome:// pages etc.
        if (!url || url.startsWith("chrome://") || url.startsWith("edge://") || url.startsWith("about:")) {
            setStatus("Open a normal http(s) webpage to score it.");
            return;
        }

        const data = await scoreUrl(url);
        setVerdict(data.verdict);
        setScore(data.trust_score);
        setReasons(data.reasons);
    } catch (e) {
        setStatus(
            `Failed: ${e.message}\nMake sure your API is running at http://127.0.0.1:8000`
        );
    }
})();
