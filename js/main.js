// Prevent inspect element and other debug tools
document.addEventListener('keydown', function(e) {
    // Prevent F12
    if (e.key === 'F12' || e.keyCode === 123) {
        e.preventDefault();
        return false;
    }

    // Prevent Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+Shift+C
    if (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C' || e.keyCode === 73 || e.keyCode === 74 || e.keyCode === 67)) {
        e.preventDefault();
        return false;
    }

    // Prevent Ctrl+U (view source)
    if (e.ctrlKey && (e.key === 'U' || e.keyCode === 85)) {
        e.preventDefault();
        return false;
    }
});

// Disable developer tools through devtools event
window.addEventListener('devtoolschange', function(e) {
    if (e.detail.open) {
        window.location.reload();
    }
});

// Additional protection against right-click
document.addEventListener('contextmenu', function(e) {
    e.preventDefault();
    return false;
});

// Prevent text selection
document.addEventListener('selectstart', function(e) {
    e.preventDefault();
    return false;
});

// Prevent copy/paste
document.addEventListener('copy', function(e) {
    e.preventDefault();
    return false;
});

document.addEventListener('cut', function(e) {
    e.preventDefault();
    return false;
});

document.addEventListener('paste', function(e) {
    e.preventDefault();
    return false;
});

document.addEventListener('DOMContentLoaded', () => {
    // Background Animation Setup
    const canvas = document.getElementById('backgroundAnimation');
    const ctx = canvas.getContext('2d');
    let nodes = [];
    const nodeCount = 50;
    const connectionDistance = 150;
    let mousePosition = { x: 0, y: 0 };

    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    // Track mouse movement
    document.addEventListener('mousemove', (e) => {
        mousePosition.x = e.clientX;
        mousePosition.y = e.clientY;
    });

    class Node {
        constructor() {
            this.reset();
        }

        reset() {
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
            this.vx = (Math.random() - 0.5) * 2;
            this.vy = (Math.random() - 0.5) * 2;
            this.radius = 3;
            this.baseColor = this.getRandomColor();
        }

        getRandomColor() {
            const colors = [
                [52, 152, 219],   // Blue
                [46, 204, 113],   // Green
                [155, 89, 182],   // Purple
                [241, 196, 15],   // Yellow
                [231, 76, 60]     // Red
            ];
            return colors[Math.floor(Math.random() * colors.length)];
        }

        draw() {
            const [r, g, b] = this.baseColor;
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${r}, ${g}, ${b}, 0.8)`;
            ctx.fill();
        }

        update() {
            // Move towards mouse when nearby
            const dx = mousePosition.x - this.x;
            const dy = mousePosition.y - this.y;
            const distance = Math.sqrt(dx * dx + dy * dy);

            if (distance < 200) {
                this.vx += dx / distance * 0.2;
                this.vy += dy / distance * 0.2;
            }

            // Update position
            this.x += this.vx;
            this.y += this.vy;

            // Add friction
            this.vx *= 0.99;
            this.vy *= 0.99;

            // Bounce off edges
            if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
            if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
        }
    }

    // Create nodes
    for (let i = 0; i < nodeCount; i++) {
        nodes.push(new Node());
    }

    function drawConnections() {
        nodes.forEach((node1, i) => {
            nodes.slice(i + 1).forEach(node2 => {
                const dx = node2.x - node1.x;
                const dy = node2.y - node1.y;
                const distance = Math.sqrt(dx * dx + dy * dy);

                if (distance < connectionDistance) {
                    const opacity = 1 - (distance / connectionDistance);
                    const [r, g, b] = node1.baseColor;
                    ctx.beginPath();
                    ctx.moveTo(node1.x, node1.y);
                    ctx.lineTo(node2.x, node2.y);
                    ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${opacity * 0.5})`;
                    ctx.lineWidth = 1;
                    ctx.stroke();
                }
            });
        });
    }

    function animate() {
        ctx.fillStyle = document.documentElement.getAttribute('data-theme') === 'dark'
            ? 'rgba(26, 26, 26, 0.95)'
            : 'rgba(245, 246, 250, 0.95)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        drawConnections();
        nodes.forEach(node => {
            node.update();
            node.draw();
        });

        requestAnimationFrame(animate);
    }

    animate();

    // Theme toggle functionality
    const themeToggle = document.getElementById('themeToggle');

    // Check for saved theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
        themeToggle.checked = true;
    }

    // Theme toggle handler
    themeToggle.addEventListener('change', () => {
        const newTheme = themeToggle.checked ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
    });

    const scanButton = document.getElementById('scanButton');
    const targetUrl = document.getElementById('targetUrl');
    const resultsContainer = document.querySelector('.results-container');
    const vulnerabilitiesDiv = document.getElementById('vulnerabilities');
    const progressBar = document.querySelector('.progress');

    scanButton.addEventListener('click', async () => {
        if (!targetUrl.value) {
            alert('Please enter a valid URL');
            return;
        }

        // Show results container and reset
        resultsContainer.style.display = 'block';
        vulnerabilitiesDiv.innerHTML = '';
        progressBar.style.width = '0%';

        // Simulated vulnerabilities check
        const checks = [
            { name: 'XSS Vulnerabilities', severity: 'high' },
            { name: 'SQL Injection Points', severity: 'high' },
            { name: 'Insecure Headers', severity: 'medium' },
            { name: 'SSL/TLS Configuration', severity: 'medium' },
            { name: 'CSRF Protection', severity: 'high' },
            { name: 'Content Security Policy', severity: 'medium' },
            { name: 'Cookie Security', severity: 'low' }
        ];

        for (let i = 0; i < checks.length; i++) {
            // Update progress
            const progress = ((i + 1) / checks.length) * 100;
            progressBar.style.width = `${progress}%`;

            // Simulate scanning delay
            await new Promise(resolve => setTimeout(resolve, 1000));

            // Add vulnerability finding
            const result = await simulateCheck(checks[i], targetUrl.value);
            addVulnerabilityItem(result);
        }
    });

    function addVulnerabilityItem(result) {
        const item = document.createElement('div');
        item.className = `vulnerability-item vulnerability-${result.severity}`;
        item.innerHTML = `
            <h3>${result.name}</h3>
            <p>${result.description}</p>
            ${result.recommendation ? `<p><strong>Recommendation:</strong> ${result.recommendation}</p>` : ''}
        `;
        vulnerabilitiesDiv.appendChild(item);
    }

    async function simulateCheck(check, url) {
        // This is a simulation. In a real application, you would perform actual security checks
        const results = {
            'XSS Vulnerabilities': {
                description: 'Potential Cross-Site Scripting vulnerabilities found in form inputs.',
                recommendation: 'Implement input validation and output encoding.'
            },
            'SQL Injection Points': {
                description: 'Possible SQL injection points detected in query parameters.',
                recommendation: 'Use parameterized queries and input validation.'
            },
            'Insecure Headers': {
                description: 'Missing security headers: X-Frame-Options, X-Content-Type-Options',
                recommendation: 'Add recommended security headers to server configuration.'
            },
            'SSL/TLS Configuration': {
                description: 'TLS 1.2 is supported but older versions should be disabled.',
                recommendation: 'Disable TLS 1.0 and 1.1, enable only TLS 1.2 and above.'
            },
            'CSRF Protection': {
                description: 'CSRF tokens not detected in forms.',
                recommendation: 'Implement CSRF tokens in all forms.'
            },
            'Content Security Policy': {
                description: 'Content Security Policy (CSP) header not implemented.',
                recommendation: 'Add CSP header to restrict resource loading.'
            },
            'Cookie Security': {
                description: 'Cookies missing secure and HttpOnly flags.',
                recommendation: 'Set secure and HttpOnly flags for sensitive cookies.'
            }
        };

        return {
            name: check.name,
            severity: check.severity,
            description: results[check.name].description,
            recommendation: results[check.name].recommendation
        };
    }
});
