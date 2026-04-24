document.addEventListener("DOMContentLoaded", function() {
    function isValidTarget(target) {
        const ipRegex = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
        const hostRegex = /^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)*[a-zA-Z0-9-]{1,63}$/;
        return ipRegex.test(target) || hostRegex.test(target);
    }

    function isValidPort(port) {
        const numericPort = Number(port);
        return Number.isInteger(numericPort) && numericPort >= 1 && numericPort <= 65535;
    }

    function showValidationMessage(message) {
        const validationEl = document.getElementById("remote-validation-message");
        if (!validationEl) return;
        validationEl.textContent = message;
        validationEl.classList.remove("d-none");
    }

    function clearValidationMessage() {
        const validationEl = document.getElementById("remote-validation-message");
        if (!validationEl) return;
        validationEl.textContent = "";
        validationEl.classList.add("d-none");
    }

    async function remoteCheck(type) {
        const targetInput = document.getElementById("single-target");
        const portInput = document.getElementById("single-port");
        const target = targetInput.value.trim();
        const portRaw = portInput ? portInput.value.trim() : '';
        const port = portRaw ? Number(portRaw) : null;

        clearValidationMessage();
        targetInput.classList.remove("error-border");
        portInput.classList.remove("error-border");

        if(!target) {
            targetInput.classList.add("error-border");
            showValidationMessage("Please enter a target IP address or hostname.");
            return;
        }

        if (!isValidTarget(target)) {
            targetInput.classList.add("error-border");
            showValidationMessage("Target format looks invalid. Use a valid IP or hostname.");
            return;
        }

        if (type === "telnet" && (port === null || !isValidPort(port))) {
            portInput.classList.add("error-border");
            showValidationMessage("Port is required and must be between 1 and 65535.");
            return;
        }

        // UI elements
        const elements = {
            ping: {
                display: document.getElementById("ping-target-display"),
                status: document.getElementById("ping-status"),
                output: document.getElementById("ping-output"),
                placeholder: document.getElementById("ping-placeholder"),
                btn: document.getElementById("btn-ping")
            },
            telnet: {
                display: document.getElementById("telnet-target-display"),
                status: document.getElementById("telnet-status"),
                output: document.getElementById("telnet-output"),
                placeholder: document.getElementById("telnet-placeholder"),
                btn: document.getElementById("btn-telnet")
            },
            traceroute: {
                display: document.getElementById("traceroute-target-display"),
                status: document.getElementById("traceroute-status"),
                output: document.getElementById("traceroute-output"),
                placeholder: document.getElementById("traceroute-placeholder"),
                btn: document.getElementById("btn-traceroute")
            }
        };

        const current = elements[type];
        
        // Show target and loading state
        current.display.innerText = (type === 'telnet' ? `${target}:${port}` : target);
        current.status.innerText = "Running...";
        current.status.classList.remove("text-success", "text-danger");
        
        // Toggle view from placeholder to output box
        current.placeholder.classList.add("d-none");
        current.output.classList.remove("d-none");
        current.output.innerText = ""; // Clear previous output
        
        // Disable button
        const originalBtnText = current.btn.innerHTML;
        current.btn.disabled = true;
        current.btn.innerHTML = '<span class="material-symbols-rounded fa-spin">progress_activity</span> Running...';

        try {
            const response = await fetch("/api/remote_check_stream", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ target, type, port })
            });

            if (!response.ok) {
                throw new Error("Server error");
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let fullOutput = "";

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                
                const chunk = decoder.decode(value, { stream: true });
                current.output.innerText += chunk;
                
                // Auto-scroll to bottom
                current.output.scrollTop = current.output.scrollHeight;
                
                // Track if it seems successful (optional)
                if (chunk.toLowerCase().includes("reply from") || chunk.toLowerCase().includes("connected to")) {
                     current.status.innerText = "Active";
                     current.status.classList.add("text-success");
                }
            }

            current.status.innerText = "Completed";
            current.status.classList.add("text-success");

        } catch(err) {
            console.error(err);
            current.status.innerText = "Failed";
            current.status.classList.add("text-danger");
            current.output.innerText = "Error: " + err.message;
        } finally {
            current.btn.disabled = false;
            current.btn.innerHTML = originalBtnText;
        }
    }

    document.getElementById("btn-ping").addEventListener("click", () => remoteCheck("ping"));
    document.getElementById("btn-telnet").addEventListener("click", () => remoteCheck("telnet"));
    document.getElementById("btn-traceroute").addEventListener("click", () => remoteCheck("traceroute"));
});
