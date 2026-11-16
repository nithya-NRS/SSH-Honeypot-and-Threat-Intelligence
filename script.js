const API = "/api";


// ==========================================
// API HELPER
// ==========================================

async function getData(endpoint) {

    try {

        const response =
            await fetch(`${API}${endpoint}`);

        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status}`
            );
        }

        return await response.json();

    } catch (error) {

        console.error(
            `Error loading ${endpoint}:`,
            error
        );

        return null;
    }
}


// ==========================================
// TOTAL EVENTS
// ==========================================

async function loadTotalEvents() {

    const data =
        await getData("/total-events");

    if (
        !data ||
        !data.results ||
        data.results.length === 0
    ) {
        return;
    }

    const total =
        data.results[0].total_events;

    const element =
        document.getElementById("totalEvents");

    if (element) {

        element.textContent =
            Number(total).toLocaleString();
    }
}


// ==========================================
// SUSPICIOUS EVENTS
// ==========================================

async function loadSuspiciousCommands() {

    const data =
        await getData(
            "/suspicious-commands"
        );

    const element =
        document.getElementById(
            "suspiciousEvents"
        );

    if (!element) {
        return;
    }

    if (
        !data ||
        !data.results
    ) {

        element.textContent = "0";

        return;
    }

    element.textContent =
        data.results.length;
}


// ==========================================
// SOURCE IPs
// ==========================================

async function loadSourceIPs() {

    const data =
        await getData(
            "/source-ips"
        );

    if (
        !data ||
        !data.results
    ) {
        return;
    }

    const element =
        document.getElementById(
            "sourceIPs"
        );

    if (element) {

        element.textContent =
            data.results.length;
    }


    const ipList =
        document.getElementById(
            "ipList"
        );

    if (!ipList) {
        return;
    }

    ipList.innerHTML = "";

    data.results
        .slice(0, 5)
        .forEach(item => {

            const row =
                document.createElement(
                    "div"
                );

            row.className =
                "ip-row";

            row.innerHTML = `
                <div class="ip-info">

                    <span>🌐</span>

                    <div>

                        <strong>
                            ${item.src_ip || "Unknown"}
                        </strong>

                        <small>
                            Source activity
                        </small>

                    </div>

                </div>

                <span class="ip-count">
                    ${item.count || 0}
                </span>
            `;

            ipList.appendChild(row);
        });
}


// ==========================================
// SSH SESSIONS
// ==========================================

async function loadSessions() {

    const data =
        await getData(
            "/ssh-sessions"
        );

    if (
        !data ||
        !data.results ||
        data.results.length === 0
    ) {
        return;
    }

    const sessions =
        data.results[0].ssh_sessions;

    const element =
        document.getElementById(
            "sshSessions"
        );

    if (element) {

        element.textContent =
            Number(sessions).toLocaleString();
    }
}


// ==========================================
// COMMAND ACTIVITY
// ==========================================

async function loadCommands() {

    const data =
        await getData(
            "/commands"
        );

    if (
        !data ||
        !data.results
    ) {
        return;
    }

    const table =
        document.getElementById(
            "commandTable"
        );

    if (!table) {
        return;
    }

    table.innerHTML = "";

    data.results
        .slice(0, 10)
        .forEach(command => {

            let timestamp =
                command.timestamp;

            if (
                Array.isArray(timestamp)
            ) {

                timestamp =
                    timestamp[0];
            }


            // ==================================
            // CUSTOM HONEYPOT COMMAND FIELD
            // ==================================

            const input =
                command.command || "-";


            // ==================================
            // USE MITRE FIELD FROM HONEYPOT
            // ==================================

            let technique =
                command.mitre_technique ||
                "General Activity";

            let risk =
                "Low";


            // ==================================
            // RISK CLASSIFICATION
            // ==================================

            if (
                command.mitre_technique
            ) {

                if (
                    /T1105|T1059|T1222|T1098|T1003|T1027/i
                        .test(command.mitre_technique)
                ) {

                    risk = "High";

                } else {

                    risk = "Medium";
                }

            } else if (
                /wget|curl|nc|netcat|bash|python|perl|chmod|passwd|base64/i
                    .test(input)
            ) {

                technique =
                    "Suspicious Activity";

                risk =
                    "High";

            } else if (
                /whoami|uname|id|ip addr|ifconfig|hostname/i
                    .test(input)
            ) {

                technique =
                    "Discovery";

                risk =
                    "Medium";
            }


            const row =
                document.createElement(
                    "tr"
                );

            row.innerHTML = `

                <td>
                    ${timestamp || "-"}
                </td>

                <td>
                    ${command.src_ip || "-"}
                </td>

                <td class="command">
                    ${input}
                </td>

                <td class="technique">
                    ${technique}
                </td>

                <td class="risk">
                    ${risk}
                </td>

            `;

            table.appendChild(row);
        });
}


// ==========================================
// ATTACK TIMELINE
// ==========================================

let attackChart = null;

async function loadAttackTimeline() {

    const data =
        await getData(
            "/attack-timeline"
        );

    if (
        !data ||
        !data.results
    ) {
        return;
    }

    const labels = [];
    const values = [];

    data.results.forEach(item => {

        if (item._time) {

            labels.push(
                item._time
            );

            values.push(
                Number(item.events || 0)
            );
        }
    });

    const canvas =
        document.getElementById(
            "attackChart"
        );

    if (!canvas) {
        return;
    }

    if (attackChart) {
        attackChart.destroy();
    }

    attackChart =
        new Chart(
            canvas,
            {
                type: "line",

                data: {

                    labels: labels,

                    datasets: [
                        {
                            label:
                                "Security Events",

                            data: values,

                            tension: 0.3,

                            fill: true
                        }
                    ]
                },

                options: {

                    responsive: true,

                    maintainAspectRatio:
                        false,

                    plugins: {

                        legend: {
                            display: true
                        }
                    },

                    scales: {

                        y: {
                            beginAtZero: true
                        }
                    }
                }
            }
        );
}


// ==========================================
// EVENT TYPE DISTRIBUTION
// ==========================================

let eventChart = null;

async function loadEventTypes() {

    const data =
        await getData(
            "/event-types"
        );

    if (
        !data ||
        !data.results
    ) {
        return;
    }

    const labels = [];
    const values = [];

    data.results
        .slice(0, 8)
        .forEach(item => {

            labels.push(
                item.event_type || "Unknown"
            );

            values.push(
                Number(item.count || 0)
            );
        });


    const canvas =
        document.getElementById(
            "eventChart"
        );

    if (!canvas) {
        return;
    }

    if (eventChart) {
        eventChart.destroy();
    }

    eventChart =
        new Chart(
            canvas,
            {
                type: "doughnut",

                data: {

                    labels: labels,

                    datasets: [
                        {
                            data: values
                        }
                    ]
                },

                options: {

                    responsive: true,

                    maintainAspectRatio:
                        false
                }
            }
        );
}


// ==========================================
// MITRE ATT&CK
// ==========================================

async function loadMitre() {

    const data =
        await getData(
            "/mitre"
        );

    const list =
        document.getElementById(
            "mitreList"
        );

    if (!list) {
        return;
    }

    list.innerHTML = "";

    if (
        !data ||
        !data.results ||
        data.results.length === 0
    ) {

        list.innerHTML =
            "<p>No techniques detected.</p>";

        return;
    }


    data.results.forEach(item => {

        const technique =
            item.mitre_technique ||
            "Unclassified";

        const count =
            item.count || 0;


        const row =
            document.createElement(
                "div"
            );

        row.className =
            "mitre-item";

        row.innerHTML = `

            <div>

                <strong>
                    ${technique}
                </strong>

                <small>
                    Detected ${count} time(s)
                </small>

            </div>

        `;

        list.appendChild(row);
    });
}


// ==========================================
// CLOCK
// ==========================================

function updateTime() {

    const clock =
        document.getElementById(
            "currentTime"
        );

    if (!clock) {
        return;
    }

    clock.textContent =
        new Date()
            .toLocaleTimeString();
}

updateTime();

setInterval(
    updateTime,
    1000
);


// ==========================================
// LOAD COMPLETE DASHBOARD
// ==========================================

async function loadDashboard() {

    console.log(
        "Loading SIEM dashboard..."
    );

    await Promise.all([

        loadTotalEvents(),

        loadSuspiciousCommands(),

        loadSourceIPs(),

        loadSessions(),

        loadCommands(),

        loadAttackTimeline(),

        loadEventTypes(),

        loadMitre()

    ]);

    console.log(
        "SIEM dashboard updated."
    );
}


loadDashboard();


// ==========================================
// AUTO REFRESH
// ==========================================

setInterval(
    loadDashboard,
    30000
);