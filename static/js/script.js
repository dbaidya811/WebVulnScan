document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const scanForm = document.getElementById('scan-form');
    const clearBtn = document.getElementById('clear-btn');
    const scanStatus = document.getElementById('scan-status');
    const alertBox = document.getElementById('alert');
    
    // Event Listeners
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            startScan();
        });
    }
    
    if (clearBtn) {
        clearBtn.addEventListener('click', clearForm);
    }
    
    // Functions
    function startScan() {
        const urlInput = document.querySelector('input[name="url"]');
        const url = urlInput.value.trim();
        
        if (!url) {
            showAlert('Please enter a valid URL to scan', 'error');
            return;
        }
        
        // Validate URL format
        if (!isValidUrl(url)) {
            showAlert('Please enter a valid URL (e.g., https://example.com)', 'error');
            return;
        }
        
        // Show scanning status
        scanStatus.classList.remove('hidden');
        showAlert('Scan started. This may take a few minutes...', 'info');
        
        // Create form data
        const formData = new FormData(scanForm);
        
        // Send the request to the server
        fetch('/scan', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                showAlert(data.error, 'error');
                scanStatus.classList.add('hidden');
            } else if (data.success) {
                // Redirect to results page
                window.location.href = '/results/' + data.session_id;
            }
        })
        .catch(error => {
            showAlert('An error occurred: ' + error.message, 'error');
            scanStatus.classList.add('hidden');
        });
    }
    
    function clearForm() {
        if (scanForm) {
            scanForm.reset();
            hideAlert();
        }
    }
    
    function isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            // If the URL doesn't have a protocol, try adding http://
            try {
                new URL('http://' + string);
                return true;
            } catch (_) {
                return false;
            }
        }
    }
    
    function showAlert(message, type) {
        if (alertBox) {
            alertBox.textContent = message;
            alertBox.className = `alert ${type}`;
            alertBox.classList.remove('hidden');
            
            // Auto-hide after 5 seconds for success messages
            if (type === 'success') {
                setTimeout(hideAlert, 5000);
            }
        }
    }
    
    function hideAlert() {
        if (alertBox) {
            alertBox.classList.add('hidden');
        }
    }
    
    // Copy to clipboard functionality for results page
    const copyButtons = document.querySelectorAll('.copy-btn');
    if (copyButtons.length > 0) {
        copyButtons.forEach(button => {
            button.addEventListener('click', function() {
                const textToCopy = this.getAttribute('data-copy');
                navigator.clipboard.writeText(textToCopy)
                    .then(() => {
                        showAlert('Copied to clipboard!', 'success');
                    })
                    .catch(err => {
                        showAlert('Failed to copy: ' + err, 'error');
                    });
            });
        });
    }
    
    // Collapsible sections in results page
    const collapsibleHeaders = document.querySelectorAll('.finding-item h4');
    if (collapsibleHeaders.length > 0) {
        collapsibleHeaders.forEach(header => {
            header.addEventListener('click', function() {
                const content = this.nextElementSibling;
                if (content.style.display === 'none') {
                    content.style.display = 'block';
                    this.classList.add('expanded');
                } else {
                    content.style.display = 'none';
                    this.classList.remove('expanded');
                }
            });
        });
    }
});
